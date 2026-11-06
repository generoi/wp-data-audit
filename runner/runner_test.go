package runner

import (
	"os"
	"path/filepath"
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
	rep, err := r.Finish([]byte(out))
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

func mustFinish(t *testing.T, tg Target) audit.Report {
	t.Helper()
	r, err := Prepare(tg)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := r.Finish([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}
