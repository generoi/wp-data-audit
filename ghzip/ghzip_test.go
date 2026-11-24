package ghzip

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	audit "github.com/generoi/wp-data-audit"
)

func sum(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}

// archive is a zip as GitHub serves one: every file below one top folder.
func archive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Create("acme-plugin-abc123/")
	for name, body := range files {
		w, err := zw.Create("acme-plugin-abc123/" + name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// releaseZip is a zip as a plugin's release workflow builds one: its files
// at the root, no top folder.
func releaseZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A plugin installed from a release asset is checked against that zip, not
// the repo's archive at the ref: the tests its release leaves out aren't
// missing, and a file it doesn't ship is added.
func TestReleaseAssetChecked(t *testing.T) {
	zips := map[string][]byte{
		"/acme/released/releases/download/v1.2.0/released.zip": releaseZip(t, map[string]string{"released.php": "<?php // released", "src/A.php": "<?php // a"}),
		"/acme/released/zip/5555":                              archive(t, map[string]string{"released.php": "<?php // released", "src/A.php": "<?php // a", "test/ATest.php": "<?php // test"}),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := zips[r.URL.Path]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	pkgs := map[string]audit.Package{"released": {Name: "acme/released", Repo: "acme/released", Ref: "5555", Release: "v1.2.0/released.zip"}}
	got := Hashes(context.Background(), srv.Client(), srv.URL, srv.URL, t.TempDir(), pkgs)
	if f := got["released"]; f.Err != "" || len(f.Files) != 2 || f.Files["src/A.php"] != sum("<?php // a") {
		t.Fatalf("released: %+v", f)
	}
	f := &audit.FileFacts{Content: "web/app", Silence: map[string]bool{}, Files: map[string]string{
		"web/app/plugins/released/released.php": sum("<?php // released"),
		"web/app/plugins/released/src/A.php":    sum("<?php // a"),
		"web/app/plugins/released/src/B.php":    sum("<?php // dropped in"),
	}}
	repo := &audit.Repo{Plugins: map[string]bool{"released": true}, MuPlugins: map[string]bool{}, Dropins: map[string]bool{}, LocalWhy: "the checkout has no composer install", Packages: pkgs}
	r := audit.Check(audit.Input{Facts: audit.Facts{At: time.Now(), Files: f, Packages: got}, Repo: repo}).Report
	var ids []string
	for _, fl := range r.Flags {
		if fl.Kind == audit.KindChecksum {
			ids = append(ids, fl.ID)
		}
	}
	if strings.Join(ids, " ") != "plugin-checksum:released:src/B.php" {
		t.Errorf("checksum flags %v, want only the added src/B.php", ids)
	}
	for _, n := range r.Notes {
		if strings.Contains(n.Text, "aren't on the site") {
			t.Errorf("a file the release doesn't ship noted missing: %s", n.Text)
		}
	}
}

// Production's plugin files against their GitHub package's archive: an
// unchanged plugin isn't flagged, a changed or added PHP file is, a missing
// one is a note;
// a private, patched or non-GitHub package is only noted; a fetched archive
// is cached, a failed one isn't.
func TestPackagesChecked(t *testing.T) {
	zips := map[string][]byte{
		"/acme/clean/zip/1111":  archive(t, map[string]string{"clean.php": "<?php // clean", "readme.txt": "docs"}),
		"/acme/edited/zip/2222": archive(t, map[string]string{"edited.php": "<?php // edited", "inc/gone.php": "<?php // gone"}),
	}
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		if r.Header.Get("Authorization") != "" {
			t.Errorf("credentials sent to %s", r.URL.Path)
		}
		switch b, ok := zips[r.URL.Path]; {
		case ok:
			w.Write(b)
		case r.URL.Path == "/acme/login/zip/4444":
			http.Error(w, "auth", http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	pkgs := map[string]audit.Package{
		"clean":   {Name: "acme/clean", Repo: "acme/clean", Ref: "1111"},
		"edited":  {Name: "acme/edited", Repo: "acme/edited", Ref: "2222"},
		"private": {Name: "acme/private", Repo: "acme/private", Ref: "3333"},
		"login":   {Name: "acme/login", Repo: "acme/login", Ref: "4444"},
		"patched": {Name: "acme/patched", Repo: "acme/patched", Ref: "5555", Patched: true},
		"premium": {Name: "vendor/premium"},
	}
	cache := t.TempDir()
	got := Hashes(context.Background(), srv.Client(), srv.URL, srv.URL, cache, pkgs)
	if got["clean"].Files["clean.php"] != sum("<?php // clean") || got["clean"].Files["readme.txt"] != sum("docs") || len(got["clean"].Files) != 2 {
		t.Fatalf("clean: %v", got["clean"])
	}
	if !strings.Contains(got["private"].Err, "not a public download (404") || !strings.Contains(got["login"].Err, "not a public download (401") {
		t.Errorf("private %q, login %q", got["private"].Err, got["login"].Err)
	}
	if _, ok := got["patched"]; ok || len(got) != 4 {
		t.Errorf("fetched %v: the patched and non-GitHub ones shouldn't be", slices.Sorted(maps.Keys(got)))
	}

	again := Hashes(context.Background(), srv.Client(), srv.URL, srv.URL, cache, pkgs)
	if !maps.EqualFunc(again["edited"].Files, got["edited"].Files, func(a, b string) bool { return a == b }) {
		t.Errorf("cached edited: %v", again["edited"])
	}
	if hits["/acme/clean/zip/1111"] != 1 || hits["/acme/edited/zip/2222"] != 1 || hits["/acme/private/zip/3333"] != 2 || hits["/acme/patched/zip/5555"] != 0 {
		t.Errorf("hits %v: each archive once, a failed one again", hits)
	}

	f := &audit.FileFacts{Content: "web/app", Silence: map[string]bool{}, Files: map[string]string{
		"web/app/plugins/clean/clean.php":              sum("<?php // clean"),
		"web/app/plugins/edited/edited.php":            sum("<?php // edited, by someone"),
		"web/app/plugins/edited/inc/shell.php":         sum("<?php system($_GET[1]);"),
		"web/app/plugins/edited/build/index.asset.php": sum("<?php return array();"),
		"web/app/plugins/private/private.php":          sum("<?php"),
		"web/app/plugins/patched/patched.php":          sum("<?php // patched"),
		"web/app/plugins/premium/premium.php":          sum("<?php"),
	}, Shapes: map[string]bool{"web/app/plugins/edited/build/index.asset.php": true}}
	repo := &audit.Repo{Plugins: map[string]bool{}, MuPlugins: map[string]bool{}, Dropins: map[string]bool{}, LocalWhy: "the checkout has no composer install", Packages: pkgs}
	for name := range pkgs {
		repo.Plugins[name] = true
	}
	r := audit.Check(audit.Input{Facts: audit.Facts{At: time.Now(), Files: f, Packages: got}, Repo: repo}).Report
	var ids []string
	for _, fl := range r.Flags {
		if fl.Kind == audit.KindChecksum {
			ids = append(ids, fl.ID)
		}
	}
	slices.Sort(ids)
	if want := "plugin-checksum:edited:edited.php plugin-checksum:edited:inc/shell.php"; strings.Join(ids, " ") != want {
		t.Errorf("checksum flags %v, want %s", ids, want)
	}
	var notes []string
	for _, n := range r.Notes {
		notes = append(notes, n.Text)
	}
	n := strings.Join(notes, "\n")
	for _, want := range []string{"login (not a public download (401", "patched (patched)", "premium (not on GitHub)", "private (not a public download (404", "edited: 1 PHP file(s) of its GitHub package aren't on the site (inc/gone.php)"} {
		if !strings.Contains(n, want) {
			t.Errorf("notes lack %q:\n%s", want, n)
		}
	}
}
