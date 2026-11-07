package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	audit "github.com/generoi/wp-data-audit"
)

const out = "\nWPDA-BEGIN\n" + `{"version":1,"generated_at":"2026-11-06T12:00:00Z",
"users":[{"id":1,"login":"admin","email":"a@staff.example","roles":["administrator"],"privileged":true}],
"content":[{"kind":"iframe","hash":"abc","snippet":"video.example","count":1,"at":[{"blog":1,"table":"posts","id":3,"field":"post_content"}]}]}` + "\nWPDA-END\n"

func TestFinishAcceptFinish(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	site := Target{Site: "alpha", Env: "production", Repo: t.TempDir()}
	other := Target{Site: "beta", Env: "production", Repo: site.Repo}

	r, err := Prepare(site)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := r.Finish([]byte(out), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Flags) != 2 {
		t.Fatalf("flags %v, want the admin and the iframe", rep.Flags)
	}
	if err := Accept(site, []string{"content:abc"}, "", "jane", true); err == nil {
		t.Fatal("accepted without a reason")
	}
	user := ""
	for _, f := range rep.Flags {
		if f.Kind == "user" {
			user = f.ID
		}
	}
	if err := Accept(site, []string{user}, "staff", "jane", true); err == nil {
		t.Fatal("accepted a user flag everywhere")
	}
	if err := Accept(site, []string{"content:abc"}, "embedded videos", "jane", true); err != nil {
		t.Fatal(err)
	}
	if err := Accept(site, []string{user}, "our admin", "jane", false); err != nil {
		t.Fatal(err)
	}
	if rep = mustFinish(t, site); len(rep.Flags) != 0 {
		t.Fatalf("accepted flags came back: %v", rep.Flags)
	}
	// The iframe is accepted on another site too; its admin isn't.
	rep = mustFinish(t, other)
	if len(rep.Flags) != 1 || rep.Flags[0].Kind != "user" {
		t.Fatalf("other site: %v", rep.Flags)
	}
	ds, err := Decisions(site)
	if err != nil || len(ds) != 2 || ds[0].Reason != "our admin" || ds[1].Reason != "embedded videos" {
		t.Fatalf("decisions %+v %v", ds, err)
	}
	if fi, err := os.Stat(filepath.Join(StateDir(site), "report.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("report.json mode: %v %v", fi, err)
	}
}

// A run that skips accounts leaves the baseline alone and keeps the last
// report's account flags, so accept and the next full run still see them.
func TestPartialRun(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	site := Target{Site: "alpha", Env: "production", Repo: t.TempDir()}
	full := mustFinish(t, site)
	snaps, _ := filepath.Glob(filepath.Join(StateDir(site), "snapshots", "*.json"))

	part := site
	part.Skip = map[string]bool{"accounts": true}
	r, err := Prepare(part)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := r.Finish([]byte(strings.Replace(out, `"id":1,`, `"id":9,`, 1)), nil) // a new admin, unjudged
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Flags {
		if f.Kind == "user" {
			t.Fatalf("judged skipped accounts: %v", f)
		}
	}
	if after, _ := filepath.Glob(filepath.Join(StateDir(site), "snapshots", "*.json")); len(after) != len(snaps) {
		t.Fatalf("a partial run saved a snapshot: %v → %v", snaps, after)
	}
	saved, err := LastReport(site)
	if err != nil || len(saved.Flags) != len(full.Flags) {
		t.Fatalf("saved report %v %v, want the full run's %d flags", saved.Flags, err, len(full.Flags))
	}
}

// Without the collector (the site's wp-cli failed), the hasher's files are
// still judged, and no snapshot replaces the last full one.
func TestFinishWithoutCollector(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	site := Target{Site: "alpha", Env: "production", Repo: t.TempDir()}
	r, err := Prepare(site)
	if err != nil {
		t.Fatal(err)
	}
	hashed := "\nWPDA-BEGIN\nVERSION 1\nCONTENT web/app\nFILES\n" + strings.Repeat("a", 64) + "  web/app/uploads/x.php\nSILENCE\nWPDA-END\n"
	r.Note("the collector failed")
	rep, err := r.Finish(nil, []byte(hashed))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Flags) != 1 || rep.Flags[0].Kind != "file" || !strings.Contains(strings.Join(rep.Notes, "\n"), "the collector failed") {
		t.Fatalf("report %+v", rep)
	}
	if snaps, _ := filepath.Glob(filepath.Join(StateDir(site), "snapshots", "*.json")); len(snaps) != 0 {
		t.Fatalf("a partial run saved a snapshot: %v", snaps)
	}
}

func mustFinish(t *testing.T, tg Target) audit.Report {
	t.Helper()
	r, err := Prepare(tg)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := r.Finish([]byte(out), nil)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}
