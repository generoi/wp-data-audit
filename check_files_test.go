package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func files(rev string, fs map[string]string) *FileFacts {
	return &FileFacts{Content: "web/app", Revision: rev, Files: fs, Silence: map[string]bool{}}
}

func TestUploadsAndUndeployed(t *testing.T) {
	f := files("", map[string]string{
		"web/app/uploads/2024/01/x.php":              "abcdef0123456789aaaa",
		"web/app/uploads/index.php":                  "e3b0c44298fc1c14",
		"web/app/plugins/akismet/akismet.php":        "1111",
		"web/app/plugins/evil/evil.php":              "2222",
		"web/app/mu-plugins/kinsta-mu-plugins.php":   "3333",
		"web/app/mu-plugins/kinsta-mu-plugins/x.php": "3334",
		"web/app/mu-plugins/ours.php":                "4444",
		"web/app/mu-plugins/dropped.php":             "5555",
		"web/app/object-cache.php":                   "6666",
	})
	f.Silence["web/app/uploads/index.php"] = true
	repo := &Repo{Plugins: map[string]bool{"akismet": true}, MuPlugins: map[string]bool{"ours.php": true}, Dropins: map[string]bool{}, LocalWhy: "no install"}
	s := site0()
	s.Checksums = Checksums{
		Core:    []string{"Warning: File doesn't verify against checksum: wp-includes/x.php", "Error: Couldn't get checksums from WordPress.org."},
		Plugins: []PluginChecksum{{Plugin: "akismet", File: "a.php"}, {Plugin: "patched", File: "b.php"}}, PluginsSkipped: 2,
	}
	repo.PatchedPlugins = map[string]bool{"patched": true}
	r := Check(Input{Facts: Facts{At: now, Site: s, Files: f}, Repo: repo}).Report
	got := ids(r)
	for _, id := range []string{"upload-php:2024/01/x.php:abcdef0123456789", "plugin:evil", "mu-plugin:dropped.php", "dropin:object-cache.php", "plugin-checksum:akismet:a.php"} {
		if got[id] != Urgent {
			t.Errorf("%s: %q", id, got[id])
		}
	}
	if len(kind(r, KindChecksum)) != 2 { // one core file, one plugin file; the fetch error is a note
		t.Errorf("checksum flags %v", kind(r, KindChecksum))
	}
	for id := range got {
		if strings.Contains(id, "patched") || strings.Contains(id, "kinsta") || strings.HasPrefix(id, "upload-php:index.php") {
			t.Errorf("unexpected flag %s", id)
		}
	}
	if n := noteTexts(r); !strings.Contains(n, "Couldn't get checksums") || !strings.Contains(n, "2 plugin(s)") {
		t.Errorf("notes %s", n)
	}
}

// The release's PHP files against a composer install of the deployed commit:
// one flag per package or theme, ignoring translations, unbuilt assets and
// the host's mu-plugin; nothing compared on a revision mismatch.
func TestReleaseComparedWithDeployedCommit(t *testing.T) {
	local := map[string]string{
		"vendor/acme/lib/src/A.php":           "aaaa",
		"web/wp/wp-includes/load.php":         "bbbb",
		"web/app/plugins/premium/premium.php": "cccc",
		"web/app/plugins/premium/inc/x.php":   "dddd",
		"web/app/themes/theme/functions.php":  "eeee",
		"web/app/languages/fi.l10n.php":       "ffff",
	}
	server := maps.Clone(local)
	server["web/app/plugins/premium/inc/x.php"] = "0bad"     // modified
	server["web/app/plugins/premium/inc/shell.php"] = "0ba2" // added
	server["web/app/themes/theme/build/index.asset.php"] = "9"
	server["web/app/themes/theme/dist/scripts/main.asset.php"] = "9b"
	server["web/app/languages/fi.l10n.php"] = "1234" // updated by WordPress
	server["web/app/mu-plugins/kinsta-mu-plugins/x.php"] = "5"
	repo := &Repo{Plugins: map[string]bool{"premium": true}, MuPlugins: map[string]bool{}, Dropins: map[string]bool{}, Revision: "abc123def", Local: local}
	check := func(f *FileFacts) Report { return Check(Input{Facts: Facts{At: now, Files: f}, Repo: repo}).Report }

	r := check(files("abc123", server))
	rel := kind(r, KindRelease)
	if len(rel) != 1 || !strings.HasPrefix(rel[0].ID, "release:web/app/plugins/premium:") || rel[0].Severity != Urgent ||
		!strings.Contains(rel[0].Message, "1 changed, 1 not in the release") || !strings.Contains(rel[0].Untrusted, "inc/shell.php") {
		t.Fatalf("release flags %+v", rel)
	}
	if n := noteTexts(r); !strings.Contains(n, "languages") || !strings.Contains(n, "build/") || strings.Contains(n, "could be forged") {
		t.Fatalf("notes %s", n)
	}
	// Changed core: the collector, which loads it, can't be trusted.
	core := maps.Clone(server)
	core["web/wp/wp-includes/load.php"] = "0bad9"
	if n := noteTexts(check(files("abc123", core))); !strings.Contains(n, "could be forged") {
		t.Fatalf("notes %s", n)
	}
	// Production on another commit: nothing compared, not even which plugins
	// the checkout deploys (production's commit may add one).
	other := maps.Clone(server)
	other["web/app/plugins/newer/newer.php"] = "7"
	r = check(files("fff999", other))
	if len(kind(r, KindRelease)) != 0 || ids(r)["plugin:newer"] != "" || !strings.Contains(noteTexts(r), "production runs fff999") {
		t.Fatalf("compared across commits: %v %s", r.Flags, noteTexts(r))
	}
}

func TestExposed(t *testing.T) {
	f := &FileFacts{Content: "web/app", Data: []DataFile{
		{Path: "web/app/uploads/wpallimport/files/asiakkaat_2019.csv", Size: 10, Mtime: 1551900000},
		{Path: "web/app/uploads/2024/05/brochure.pdf", Size: 1, Mtime: 1},          // media library
		{Path: "web/app/uploads/2024/05/customers-export.xlsx", Size: 2, Mtime: 2}, // ...but its name
		{Path: "web/app/uploads/gravity_forms/1-abc/cv.pdf", Size: 3, Mtime: 1600000000},
		{Path: "web/app/uploads/sites/2/complianz/snapshots/policy.pdf"},
		{Path: "web/app/uploads/elementor/data.json"},
		{Path: "web/app/uploads/wc-logs/x.log", Size: 4, Mtime: 4},
		{Path: "web/backup.sql", Size: 5, Mtime: 5},
		{Path: "web/wp-config.php", Size: 6, Mtime: 6},
		{Path: "web/app/plugins/woocommerce/sample-data/x.csv", Size: 7, Mtime: 7}, // no install to compare
		{Path: "web/app/uploads/old.zip", Size: 8, Mtime: 8},
	}}
	cands, notes := Candidates(f, nil)
	var paths []string
	for _, c := range cands {
		paths = append(paths, c.Path)
	}
	if strings.Join(paths, " ") != "web/backup.sql web/app/uploads/old.zip web/app/uploads/2024/05/customers-export.xlsx web/app/uploads/wpallimport/files/asiakkaat_2019.csv web/app/uploads/wc-logs/x.log" {
		t.Fatalf("candidates %v", paths)
	}
	n := strings.Join(notes, "\n")
	for _, want := range []string{"1 documents in the media library", "1 Gravity Forms uploads", "oldest from 2020-09-13", "1 files in folders a plugin serves", "1 JSON files", "1 data files in plugins"} {
		if !strings.Contains(n, want) {
			t.Errorf("notes lack %q:\n%s", want, n)
		}
	}
	w := &WebFacts{Base: "https://site.example", Files: map[string]Answer{
		"web/backup.sql": {Status: 200, Type: "application/sql"},
		"web/app/uploads/old.zip": {Status: 301},
		"web/app/uploads/2024/05/customers-export.xlsx":        {Status: 200, Type: "text/csv"},
		"web/app/uploads/wpallimport/files/asiakkaat_2019.csv": {Status: 200, Type: "text/csv"},
		"web/app/uploads/wc-logs/x.log":                        {Status: 403},
	}, Listings: map[string]Listing{"web/app/uploads/wpallimport/files": {Listed: true}}}
	r := Check(Input{Facts: Facts{At: now, Files: f, Web: w}}).Report
	got := map[string]Severity{}
	for _, f := range kind(r, KindExposed) {
		got[strings.SplitN(f.Untrusted, " ", 2)[0]] = f.Severity
	}
	for p, want := range map[string]Severity{
		"web/backup.sql": Urgent,
		"web/app/uploads/wpallimport/files:":            Urgent, // one flag for the plugin folder
		"web/app/uploads/2024/05/customers-export.xlsx": Review, // media library: public on purpose
		"web/app/uploads/old.zip":                       Review, // a redirect isn't the file
		"web/app/uploads/wpallimport/files":             Urgent, // listed
	} {
		if got[p] != want {
			t.Errorf("%s: %q, want %s (all %v)", p, got[p], want, got)
		}
	}
	if len(got) != 5 || !strings.Contains(noteTexts(r), "1 logs on the server") {
		t.Errorf("flags %v, notes %s", got, noteTexts(r))
	}
}

func TestPersonalNames(t *testing.T) {
	for name, want := range map[string]bool{
		"asiakkaat_02_2019.csv": true, "members-2024.xlsx": true, "quotes-export-2025.zip": true,
		"jäsenrekisteri.xls": true, "orders.csv": true, "cv_jane.pdf": true, "users.json": true,
		"X100-User-Manual.pdf": false, "kaspar-hauser-story.pdf": false, "order-form.pdf": false,
		"application-note.pdf": false, "client-manager-job-description.pdf": false,
	} {
		if personal(name) != want {
			t.Errorf("personal(%q) = %v", name, !want)
		}
	}
}

// The hasher's output: sha256sum lines per section, an escaped odd name, a
// name that tries to forge a line, and DATA lines.
func TestParseFiles(t *testing.T) {
	h := strings.Repeat("a", 64)
	out := "motd noise\n\nWPDA-BEGIN\nVERSION 1\nCONTENT web/app\nFILES\n" +
		h + "  web/app/plugins/p/p.php\n" +
		`\` + h + `  web/app/uploads/x\nSILENCE\n` + h + `  web/app/uploads/shell.php` + "\n" + // one file, newline in its name
		h + "  web/app/uploads//y.php\n" +
		"SILENCE\n" + h + "  web/app/uploads/index.php\n" +
		"DATA\nDATA 123 1551900000.12345 web/app/uploads//a b.csv\nWPDA-END\n"
	f, err := ParseFiles([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if f.Content != "web/app" || len(f.Files) != 3 || f.Files["web/app/uploads/y.php"] != h || !f.Silence["web/app/uploads/index.php"] {
		t.Fatalf("files %+v", f)
	}
	if f.Silence["web/app/uploads/shell.php"] || f.Files["web/app/uploads/x\nSILENCE\n"+h+"  web/app/uploads/shell.php"] != h {
		t.Fatalf("a file name forged a line: %+v", f)
	}
	if len(f.Data) != 1 || f.Data[0] != (DataFile{Path: "web/app/uploads/a b.csv", Size: 123, Mtime: 1551900000}) {
		t.Fatalf("data %+v", f.Data)
	}
	if _, err := ParseFiles([]byte("\nWPDA-BEGIN\nVERSION 1\nFILES\n")); err == nil {
		t.Fatal("parsed output that was cut short")
	}
}

// The current hasher's one uploads walk: guards as SILENT lines, empty PHP
// files known by their hash (only under uploads), lines in any order.
func TestParseFilesOneWalk(t *testing.T) {
	h := strings.Repeat("a", 64)
	out := "\nWPDA-BEGIN\nVERSION 1\nCONTENT web/app\nFILES\n" +
		emptySHA + "  web/app/plugins/p/empty.php\n" +
		"DATA 5 1551900000 web/app/uploads/a.sql\n" +
		"SILENT web/app/uploads//guard.php\n" +
		h + "  web/app/uploads/guard.php\n" +
		emptySHA + "  web/app/uploads/2020/index.php\n" +
		"TIME uploads 2.5\nWPDA-END\n"
	f, err := ReadFiles(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Silence["web/app/uploads/guard.php"] || !f.Silence["web/app/uploads/2020/index.php"] || f.Silence["web/app/plugins/p/empty.php"] {
		t.Fatalf("silence %v", f.Silence)
	}
	if len(f.Files) != 3 || len(f.Data) != 1 {
		t.Fatalf("files %v data %v", f.Files, f.Data)
	}
	if _, err := ReadFiles(strings.NewReader("\nWPDA-BEGIN\n" + strings.Repeat("x", maxLine+1) + "\nWPDA-END\n")); err == nil {
		t.Fatal("read a line over maxLine")
	}
}

func TestScriptAndParseSite(t *testing.T) {
	s, err := Script(map[string][]string{"members.example": {"subscriber"}, "3": {"member"}}, SectionContent, SectionChecksums)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "<?php\n$wpda_skip = ['content' => true, 'checksums' => true, ];\n$wpda_public_roles = ['3' => ['member', ], 'members.example' => ['subscriber', ], ];\n") {
		t.Fatalf("script head: %.160s", s)
	}
	for _, bad := range []func() error{
		func() error { _, err := Script(nil, "x'];system('id');//"); return err },
		func() error { _, err := Script(map[string][]string{"x": {"x'];system('id');//"}}); return err },
		func() error { _, err := Script(map[string][]string{"x'] + [": {"a"}}); return err },
	} {
		if bad() == nil {
			t.Error("unsafe input went into the script")
		}
	}
	if php, err := exec.LookPath("php"); err == nil {
		p := filepath.Join(t.TempDir(), "c.php")
		os.WriteFile(p, []byte(s), 0o644)
		if out, err := exec.Command(php, "-l", p).CombinedOutput(); err != nil {
			t.Fatalf("php -l: %s", out)
		}
	}
	site, err := ParseSite([]byte("Notice: noise\n\nWPDA-BEGIN\n{\"version\":1,\"role_counts\":{\"customer\":3}}\nWPDA-END\n"))
	if err != nil || site.RoleCounts["customer"] != 3 {
		t.Fatalf("parse: %v %+v", err, site)
	}
	if _, err := ParseSite([]byte("\nWPDA-BEGIN\n{\"version\":1")); err == nil {
		t.Fatal("parsed output that was cut short")
	}
}

func TestReadRepo(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("composer.json", `{"extra":{"installer-paths":{
		"web/app/mu-plugins/{$name}/":["type:wordpress-muplugin","wp-plugin/moved"],
		"web/app/plugins/{$name}/":["type:wordpress-plugin"]},
		"dropin-paths":{"web/app/":["package:wp-plugin/cache:wp-cache-phase1.php"],"web/app/mu-plugins":["package:vendor/cli:plugin/login-server.php"]},
		"patches":{"wp-plugin/fixed":{},"roots/wordpress-no-content":{}}}}`)
	write("data-audit.json", `{"public_roles":{"members.example":["subscriber"]},"client_domains":["client.example"]}`)
	write("composer.lock", `{"packages":[
		{"name":"wp-plugin/fixed","type":"wordpress-plugin"},
		{"name":"wp-plugin/moved","type":"wordpress-plugin"},
		{"name":"vendor/mu","type":"wordpress-muplugin"},
		{"name":"vendor/renamed-package","type":"wordpress-plugin","extra":{"installer-name":"renamed"}},
		{"name":"vendor/lib","type":"library"}],
		"packages-dev":[{"name":"wp-plugin/dev-only","type":"wordpress-plugin"}]}`)
	write("web/app/mu-plugins/local.php", "<?php")
	write("web/app/plugins/custom/custom.php", "<?php")
	write("web/app/plugins/woocommerce/sample-data/x.csv", "a,b")
	write("web/app/object-cache.php", "<?php")
	write("vendor/composer/installed.json", "{}")
	write("vendor/composer/autoload_static.php", "<?php")
	write("vendor/acme/lib/A.php", "<?php // a")
	write("web/app/uploads/2024/x.php", "<?php")
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	repo, err := ReadRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	if repo.Local != nil || repo.Dir == "" || !repo.Comparable("") {
		t.Fatalf("before hashing: local %d files, dir %q", len(repo.Local), repo.Dir)
	}
	repo.HashInstall()
	check := func(name string, set map[string]bool, want ...string) {
		t.Helper()
		if len(set) != len(want) {
			t.Errorf("%s: %v, want %v", name, set, want)
		}
		for _, w := range want {
			if !set[w] {
				t.Errorf("%s: missing %s in %v", name, w, set)
			}
		}
	}
	check("plugins", repo.Plugins, "fixed", "custom", "renamed", "woocommerce")
	check("mu-plugins", repo.MuPlugins, "moved", "mu", "local.php", "login-server.php")
	check("dropins", repo.Dropins, "object-cache.php", "wp-cache-phase1.php")
	check("patched", repo.PatchedPlugins, "fixed")
	if !repo.PatchedCore {
		t.Error("core patch not seen")
	}
	if got := repo.PublicRoles["members.example"]; len(got) != 1 || got[0] != "subscriber" || len(repo.ClientDomains) != 1 {
		t.Errorf("data-audit settings: %v %v", repo.PublicRoles, repo.ClientDomains)
	}
	sum := sha256.Sum256([]byte("<?php // a")) // hashed like hasher.sh's sha256sum
	if got := repo.Local["vendor/acme/lib/A.php"]; got != hex.EncodeToString(sum[:]) {
		t.Errorf("local hash %q", got)
	}
	for p := range repo.Local {
		if strings.HasPrefix(p, "vendor/composer/") || strings.Contains(p, "/uploads/") {
			t.Errorf("hashed %s", p)
		}
	}
	if len(repo.Revision) != 40 || !repo.Comparable(repo.Revision[:12]) || !repo.Has("web/app/plugins/woocommerce/sample-data/x.csv") || repo.Has("web/app/nope.csv") {
		t.Errorf("revision %q, comparable/has wrong", repo.Revision)
	}
}
