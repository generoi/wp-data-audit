package runner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	audit "github.com/generoi/wp-data-audit"
	"github.com/generoi/wp-data-audit/store"
)

const collected = "\nWPDA-BEGIN\n" + `{"version":1,
"users":[{"id":1,"login":"admin","email":"a@staff.example","roles":["administrator"],"privileged":true}],
"content":[{"kind":"iframe","hash":"abc","snippet":"video.example","count":1,"at":[{"blog":1,"table":"posts","id":3,"field":"post_content"}]}]}` + "\nWPDA-END\n"

var hashed = "\nWPDA-BEGIN\nVERSION 1\nCONTENT web/app\nFILES\n" + strings.Repeat("a", 64) + "  web/app/uploads/x.php\nSILENCE\nWPDA-END\n"

// offline fails every request, so no test can reach the network.
var offline = &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
	return nil, errors.New("offline")
})}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// noGH stands in for gh: no test runs the real one.
func noGH(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("no gh in tests") }

// Access: gh's two reads (collaborators, deploy keys) and the caller's
// Kinsta func, judged with the rest; --only access runs neither script.
func TestRunAccess(t *testing.T) {
	e := newEnv(t)
	site := target(t, "alpha")
	var asked []string
	gh := func(_ context.Context, dir string, args ...string) ([]byte, error) {
		if dir != site.Repo {
			t.Errorf("gh ran in %s", dir)
		}
		asked = append(asked, args[2])
		if strings.Contains(args[2], "/collaborators") {
			return []byte("contractor\twrite\n"), nil
		}
		return []byte("7\tserver\tfalse\t2024-01-01T10:00:00Z\t\n8\tci\ttrue\t2024-01-01T10:00:00Z\t\n"), nil
	}
	kinsta := func(context.Context) (*audit.KinstaAccess, error) {
		return &audit.KinstaAccess{SFTP: []audit.SFTPAccount{{Env: "live", Username: "uploader", Permission: "write", Active: true}}}, nil
	}
	skip, _ := audit.ParseSkip("access", "")
	res, err := Run(context.Background(), site, Transport{}, Options{Skip: skip, Client: offline, Store: e.st, Config: e.cfg, GH: gh, Kinsta: kinsta})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range res.Report.Flags {
		got[f.ID] = true
	}
	if len(got) != 3 || !got["collaborator:contractor:write"] || !got["deploy-key:7"] || !got["sftp:live:uploader:write"] {
		t.Fatalf("flags %v", got)
	}
	if len(asked) != 2 || !strings.HasPrefix(asked[0], "repos/{owner}/{repo}/collaborators?affiliation=outside") {
		t.Fatalf("gh asked %q", asked)
	}
}

func fixed(out string) func(context.Context, string, io.Writer) error {
	return func(_ context.Context, _ string, w io.Writer) error { _, err := io.WriteString(w, out); return err }
}

// A script printing without end is cut at MaxOutput: the run fails that
// source, and memory stays bounded.
func TestRunCapsOutput(t *testing.T) {
	e := newEnv(t)
	site := target(t, "alpha")
	endless := func(_ context.Context, _ string, w io.Writer) error {
		chunk := []byte(strings.Repeat("x", 1<<20) + "\n")
		for {
			if _, err := w.Write(chunk); err != nil {
				return err
			}
		}
	}
	rep := e.run(t, site, Transport{Collect: fixed(collected), Hash: endless}, nil)
	var problems []string
	for _, n := range rep.Problems() {
		problems = append(problems, n.Text)
	}
	if !strings.Contains(strings.Join(problems, "\n"), "the hasher failed: output over 256 MB") {
		t.Fatalf("problems %q", problems)
	}
}

type env struct {
	st  *store.Store
	cfg *Config
}

func newEnv(t *testing.T) env {
	return env{st: &store.Store{Root: t.TempDir()}, cfg: &Config{}}
}

func (e env) run(t *testing.T, tg Target, tr Transport, skip audit.Skip) audit.Report {
	t.Helper()
	res, err := Run(context.Background(), tg, tr, Options{Skip: skip, Client: offline, Store: e.st, Config: e.cfg, GH: noGH})
	if err != nil {
		t.Fatal(err)
	}
	return res.Report
}

func target(t *testing.T, site string) Target {
	return Target{Site: site, Env: "production", Repo: t.TempDir()}
}

func idOf(r audit.Report, k audit.Kind) string {
	for _, f := range r.Flags {
		if f.Kind == k {
			return f.ID
		}
	}
	return ""
}

func TestRunAcceptRun(t *testing.T) {
	e := newEnv(t)
	site, other := target(t, "alpha"), target(t, "beta")
	tr := Transport{Collect: fixed(collected)}

	rep := e.run(t, site, tr, nil)
	user, content := idOf(rep, audit.KindUser), idOf(rep, audit.KindContent)
	if len(rep.Flags) != 2 || user == "" || content == "" {
		t.Fatalf("flags %+v, want the admin and the iframe", rep.Flags)
	}
	if err := e.st.Accept(site.Key(), []string{content}, "", "jane", true); err == nil {
		t.Fatal("accepted without a reason")
	}
	if err := e.st.Accept(site.Key(), []string{user}, "staff", "jane", true); err == nil {
		t.Fatal("accepted a user flag everywhere")
	}
	if err := e.st.Accept(site.Key(), []string{content}, "embedded videos", "jane", true); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Accept(site.Key(), []string{user}, "our admin", "jane", false); err != nil {
		t.Fatal(err)
	}
	if rep = e.run(t, site, tr, nil); len(rep.Flags) != 0 {
		t.Fatalf("accepted flags came back: %+v", rep.Flags)
	}
	// The iframe is accepted on another site too; its admin isn't.
	if rep = e.run(t, other, tr, nil); len(rep.Flags) != 1 || rep.Flags[0].Kind != audit.KindUser {
		t.Fatalf("other site: %+v", rep.Flags)
	}
	ds, err := e.st.Decisions(site.Key())
	if err != nil || len(ds) != 2 {
		t.Fatalf("decisions %+v %v", ds, err)
	}
	fi, err := os.Stat(filepath.Join(e.st.Dir(site.Key()), "report.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("report.json: %v %v", fi, err)
	}
}

// A run skipping accounts saves no baseline and keeps the last report's
// account flags, so accept and the next full run still see them.
func TestPartialRun(t *testing.T) {
	e := newEnv(t)
	site := target(t, "alpha")
	full := e.run(t, site, Transport{Collect: fixed(collected)}, nil)
	before, _ := e.st.Baseline(site.Key())

	newAdmin := strings.Replace(collected, `"id":1,`, `"id":9,`, 1)
	rep := e.run(t, site, Transport{Collect: fixed(newAdmin)}, audit.Skip{audit.Accounts: true})
	if idOf(rep, audit.KindUser) != "" {
		t.Fatalf("judged skipped accounts: %+v", rep.Flags)
	}
	if after, _ := e.st.Baseline(site.Key()); !after.At.Equal(before.At) {
		t.Fatal("a partial run saved a baseline")
	}
	saved, err := e.st.Report(site.Key())
	if err != nil || len(saved.Flags) != len(full.Flags) {
		t.Fatalf("saved %+v %v, want the full run's %d flags", saved.Flags, err, len(full.Flags))
	}
}

// Without the collector (the site's wp-cli failed), the hasher's files are
// still judged, and no baseline is made.
func TestRunWithoutCollector(t *testing.T) {
	e := newEnv(t)
	site := target(t, "alpha")
	failing := func(context.Context, string, io.Writer) error { return errors.New("PHP Fatal error") }
	rep := e.run(t, site, Transport{Collect: failing, Hash: fixed(hashed)}, nil)
	var problems []string
	for _, n := range rep.Problems() {
		problems = append(problems, n.Text)
	}
	if idOf(rep, audit.KindFile) == "" || !strings.Contains(strings.Join(problems, "\n"), "the collector failed: PHP Fatal error") {
		t.Fatalf("report %+v", rep)
	}
	if b, _ := e.st.Baseline(site.Key()); b != nil {
		t.Fatal("a run without the collector saved a baseline")
	}
}

func TestRunNothingRan(t *testing.T) {
	e := newEnv(t)
	_, err := Run(context.Background(), target(t, "alpha"), Transport{}, Options{Client: offline, Store: e.st, Config: e.cfg, GH: noGH})
	if err == nil || !strings.Contains(err.Error(), "neither") {
		t.Fatalf("err %v", err)
	}
}

// Skipping every database group never calls the collector.
func TestSkipNeedsNoCollector(t *testing.T) {
	e := newEnv(t)
	var calls atomic.Int32
	collect := func(ctx context.Context, s string, w io.Writer) error { calls.Add(1); return fixed(collected)(ctx, s, w) }
	skip, err := audit.ParseSkip("files", "")
	if err != nil {
		t.Fatal(err)
	}
	e.run(t, target(t, "alpha"), Transport{Collect: collect, Hash: fixed(hashed)}, skip)
	if calls.Load() != 0 {
		t.Fatal("ran the collector for --only files")
	}
}

// A signal mid-run stops both scripts and saves nothing.
func TestStopSavesNothing(t *testing.T) {
	e := newEnv(t)
	site := target(t, "alpha")
	ctx, cancel := context.WithCancel(context.Background())
	slow := func(ctx context.Context, _ string, _ io.Writer) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	_, err := Run(ctx, site, Transport{Collect: slow, Hash: slow}, Options{Client: offline, Store: e.st, Config: e.cfg, GH: noGH})
	if err == nil || !strings.Contains(err.Error(), "nothing saved") {
		t.Fatalf("err %v", err)
	}
	if _, err := e.st.Report(site.Key()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("saved a report: %v", err)
	}
}

// The probes run from what each script found: the public checks from the
// collector's home URL, the exposed files from the hasher's list.
func TestPipelineProbes(t *testing.T) {
	var asked sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Store(r.URL.Path, true)
		if strings.HasSuffix(r.URL.Path, ".csv") {
			w.Header().Set("Content-Type", "text/csv")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	e := newEnv(t)
	site := target(t, "alpha")
	withHome := strings.Replace(collected, `{"version":1,`, `{"version":1,"home":"`+srv.URL+`","options":{"home":"`+srv.URL+`"},`, 1)
	withData := strings.Replace(hashed, "WPDA-END", "DATA 10 1700000000 web/app/uploads/wpallexport/exports/users.csv\nWPDA-END", 1)
	res, err := Run(context.Background(), site, Transport{Collect: fixed(withHome), Hash: fixed(withData)},
		Options{Client: srv.Client(), Store: e.st, Config: e.cfg, GH: noGH})
	if err != nil {
		t.Fatal(err)
	}
	if idOf(res.Report, audit.KindExposed) == "" {
		t.Fatalf("no exposed flag: %+v", res.Report.Flags)
	}
	for _, p := range []string{"/app/uploads/wpallexport/exports/users.csv", "/wp-json/wp/v2/users"} {
		if _, ok := asked.Load(p); !ok {
			t.Errorf("never asked %s", p)
		}
	}
}

// A report saved before notes had a group (plain strings) still reads.
func TestOldReport(t *testing.T) {
	e := newEnv(t)
	site := target(t, "alpha")
	old := `{"flags":[{"id":"user:1:x","severity":"urgent","kind":"user","message":"m"}],"notes":["the collector failed: x"]}`
	if err := os.MkdirAll(e.st.Dir(site.Key()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.st.Dir(site.Key()), "report.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := e.st.Report(site.Key())
	if err != nil || len(rep.Problems()) != 1 || rep.Problems()[0].Text != "the collector failed: x" {
		t.Fatalf("%+v %v", rep, err)
	}
	e.run(t, site, Transport{Collect: fixed(collected)}, nil)
}

func TestBaselinesPruned(t *testing.T) {
	st := store.Store{Root: t.TempDir()}
	k := store.Key{Site: "alpha", Env: "production"}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range store.KeepBaselines + 3 {
		if err := st.SaveBaseline(k, &audit.Baseline{At: at.Add(time.Duration(i) * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(st.Dir(k), "baselines", "*.json"))
	b, _ := st.Baseline(k)
	if len(files) != store.KeepBaselines || !b.At.Equal(at.Add(time.Duration(store.KeepBaselines+2)*time.Hour)) {
		t.Fatalf("%d baselines, newest %v", len(files), b.At)
	}
}
