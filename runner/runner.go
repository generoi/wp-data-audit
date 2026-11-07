// Package runner is one audit end to end, however the caller reaches the
// site: Run takes a Transport (how to pipe a script to the site's wp-cli and
// to a shell in its release) and does the rest the same way for every
// caller: read the checkout, run both scripts and the probes that depend on
// them as a pipeline, judge, and save to the store the CLI and foreman share.
package runner

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	audit "github.com/generoi/wp-data-audit"
	"github.com/generoi/wp-data-audit/geo"
	"github.com/generoi/wp-data-audit/store"
	"github.com/generoi/wp-data-audit/web"
)

// Config is ~/.config/wp-data-audit/config.json: what's true for every site.
// What's true for one site lives in its repo (audit.ReadRepo).
type Config struct {
	AllowedCountries []string `json:"allowed_countries"`
	AllowedIPs       []string `json:"allowed_ips"`
	StaffDomains     []string `json:"staff_domains"`
	StaffEmails      []string `json:"staff_emails"` // the current staff: a staff-domain account not on it is flagged
	GeoIP            string   `json:"geoip"`        // default geo.DefaultPath()
}

// LoadConfig reads the config; none is an empty one.
func LoadConfig() (Config, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		h, _ := os.UserHomeDir()
		dir = filepath.Join(h, ".config")
	}
	var c Config
	b, err := os.ReadFile(filepath.Join(dir, "wp-data-audit", "config.json"))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("config.json: %w", err)
	}
	return c, nil
}

// Target is one site environment and its checkout, at the deployed commit
// for the file comparison. Deployed is that commit from outside the server
// (DeployedCommit); it wins over a Deployer REVISION file there.
type Target struct {
	Site, Env string
	Repo      string
	Deployed  string
}

// Key is the target's place in the store.
func (t Target) Key() store.Key { return store.Key{Site: t.Site, Env: t.Env} }

// Transport reaches the site. A nil func can't: its source doesn't run, and
// the checks needing it say so. Each func writes the script's output to out
// as it comes (the runner parses it meanwhile, nothing held whole) and
// returns when the script has ended; a write error means stop: the output
// passed MaxOutput, or the run was stopped.
type Transport struct {
	// Collect pipes the collector script to the site's wp-cli with
	// audit.WPArgs.
	Collect func(ctx context.Context, script string, out io.Writer) error
	// Hash pipes audit.Hasher to audit.HasherCommand in the release.
	Hash func(ctx context.Context, script string, out io.Writer) error
}

// MaxOutput is the most a script may print: far above any real site's
// (a large multisite's hasher prints about 2 MB), low enough that a site
// printing without end can't fill memory.
const MaxOutput = 256 << 20

// stream runs send with a writer feeding read, as a pipe: read parses while
// send writes, and send's writes fail past MaxOutput. What read leaves unread
// is drained, so send never blocks on it.
func stream[T any](ctx context.Context, send func(context.Context, io.Writer) error, read func(io.Reader) (T, error)) (T, error) {
	pr, pw := io.Pipe()
	type parsed struct {
		v   T
		err error
	}
	got := make(chan parsed, 1)
	go func() {
		v, err := read(pr)
		io.Copy(io.Discard, pr)
		got <- parsed{v, err}
	}()
	err := send(ctx, &capped{w: pw, left: MaxOutput})
	pw.CloseWithError(err) // nil: the reader sees EOF
	p := <-got
	if err != nil {
		var zero T
		return zero, err
	}
	return p.v, p.err
}

// capped fails writes past left bytes.
type capped struct {
	w    io.Writer
	left int64
}

func (c *capped) Write(b []byte) (int, error) {
	if int64(len(b)) > c.left {
		return 0, fmt.Errorf("output over %d MB", MaxOutput>>20)
	}
	c.left -= int64(len(b))
	return c.w.Write(b)
}

// Options are a run's choices; zero values are the defaults.
type Options struct {
	Skip   audit.Skip
	Client *http.Client  // for the public URLs; web.NewClient when nil
	Store  *store.Store  // store.Default when nil
	Config *Config       // LoadConfig when nil
}

// Result is a run's report (what this run judged; the saved one keeps the
// last full run's flags for what it didn't) and where its time went.
type Result struct {
	Report    audit.Report
	Timings   []Timing
	Collector map[string]float64 // seconds per collector section
	PeakMB    float64            // the collector's peak memory on the site
	Hasher    map[string]float64 // seconds per hasher section
}

// Timing is one phase's duration.
type Timing struct {
	Phase string
	Took  time.Duration
}

// Run audits t through tr. A signal (ctx ending) stops both scripts and the
// probes, and nothing is saved.
func Run(ctx context.Context, t Target, tr Transport, o Options) (Result, error) {
	r := &run{t: t, tr: tr, o: o, at: time.Now().UTC()}
	if r.o.Store == nil {
		s := store.Default()
		r.o.Store = &s
	}
	if r.o.Config == nil {
		cfg, err := LoadConfig()
		if err != nil {
			return Result{}, err
		}
		r.o.Config = &cfg
	}
	script, err := r.prepare()
	if err != nil {
		return Result{}, err
	}
	facts := r.gather(ctx, script)
	if ctx.Err() != nil {
		return Result{}, fmt.Errorf("stopped: %w (nothing saved)", context.Cause(ctx))
	}
	collector, hasher, _ := o.Skip.Needs()
	if facts.Site == nil && facts.Files == nil && (collector || hasher) {
		return Result{}, fmt.Errorf("neither the collector nor the hasher ran: %s", r.problems())
	}
	rep, err := r.judge(facts)
	if err != nil {
		return Result{}, err
	}
	res := Result{Report: rep, Timings: r.timings}
	if facts.Site != nil {
		res.Collector, res.PeakMB = facts.Site.Timings, facts.Site.PeakMB
	}
	if facts.Files != nil {
		res.Hasher = facts.Files.Timings
	}
	return res, nil
}

// CollectorScript is the collector for t, as Run would pipe it.
func CollectorScript(t Target, skip audit.Skip) (string, error) {
	r := &run{t: t, o: Options{Skip: skip}}
	return r.prepare()
}

type run struct {
	t       Target
	tr      Transport
	o       Options
	at      time.Time
	repo    *audit.Repo
	mu      sync.Mutex // notes and timings, from the scripts' goroutines
	notes   []audit.Note
	timings []Timing
}

func (r *run) problem(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notes = append(r.notes, audit.Note{Problem: true, Text: fmt.Sprintf(format, args...)})
}

func (r *run) problems() string {
	var s []string
	for _, n := range r.notes {
		s = append(s, n.Text)
	}
	return strings.Join(s, "; ")
}

func (r *run) time(phase string, start time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.timings = append(r.timings, Timing{phase, time.Since(start)})
}

// prepare reads the checkout (its install is hashed later, alongside the
// site's scripts) and builds the collector, leaving out what won't be judged.
// wordpress.org's checksums are slow and only stand in for comparing with a
// local install, so they're left out whenever that comparison can run.
func (r *run) prepare() (string, error) {
	start := time.Now()
	repo, err := audit.ReadRepo(r.t.Repo)
	r.time("read the checkout", start)
	if err != nil {
		r.problem("can't read the repo, so plugins weren't compared and no role counts as public: %v", err)
	}
	r.repo = repo
	var roles map[string][]string
	if repo != nil {
		roles = repo.PublicRoles
	}
	var skip []audit.Section
	if !r.o.Skip.Runs(audit.Content) {
		skip = append(skip, audit.SectionContent)
	}
	if !r.o.Skip.Runs(audit.Retention) {
		skip = append(skip, audit.SectionRetention)
	}
	if !r.o.Skip.Runs(audit.Files) || repo.Comparable(r.t.Deployed) {
		skip = append(skip, audit.SectionChecksums)
	}
	return audit.Script(roles, skip...)
}

// gather reads everything, before the store's lock, as a pipeline of what
// depends on what: the collector, then the public-site probes (they only
// need its URLs); the hasher, then the exposed-file probes (its files and the
// collector's URLs); and the checkout's install hashed meanwhile. A failure
// is a problem note, and the other sources still count.
func (r *run) gather(ctx context.Context, script string) audit.Facts {
	facts := audit.Facts{At: r.at}
	collector, hasher, _ := r.o.Skip.Needs()
	var wg sync.WaitGroup
	var where web.Target // the site's URLs, set before located is closed
	located := make(chan struct{})
	var public, exposed *audit.WebFacts

	wg.Go(func() {
		if collector {
			facts.Site = r.collect(ctx, script)
		}
		where = r.where(facts.Site)
		close(located)
		if r.o.Skip.Runs(audit.Public) && ctx.Err() == nil {
			start := time.Now()
			public = web.Probe(ctx, r.o.Client, where, web.Options{Public: true})
			r.time("public URLs", start)
		}
	})
	if hasher {
		wg.Go(func() {
			facts.Files = r.hash(ctx)
			if facts.Files == nil || !r.o.Skip.Runs(audit.Exposed) {
				return
			}
			<-located
			if ctx.Err() != nil {
				return
			}
			t := where
			t.Content = facts.Files.Content
			var o web.Options
			cands, _ := audit.Candidates(facts.Files, r.repo)
			for _, c := range cands {
				o.Files = append(o.Files, c.Path)
			}
			start := time.Now()
			exposed = web.Probe(ctx, r.o.Client, t, o)
			r.time("exposed-file URLs", start)
		})
	}
	if r.o.Skip.Runs(audit.Files) && r.repo != nil && r.repo.Dir != "" {
		wg.Go(func() {
			start := time.Now()
			r.repo.HashInstall()
			r.time("hash the checkout's install", start)
		})
	}
	wg.Wait()
	facts.Web = merge(exposed, public)
	return facts
}

// collect runs the collector; nil when it couldn't.
func (r *run) collect(ctx context.Context, script string) *audit.SiteFacts {
	if r.tr.Collect == nil {
		r.problem("the collector can't reach this site")
		return nil
	}
	start := time.Now()
	s, err := stream(ctx, func(ctx context.Context, w io.Writer) error { return r.tr.Collect(ctx, script, w) }, audit.ReadSite)
	r.time("collector", start)
	if err != nil && ctx.Err() == nil {
		r.problem("the collector failed: %v", err)
	}
	return s
}

// hash runs the hasher; nil when it couldn't. The deployed commit is GitHub's
// word over a REVISION file on the server, which an attacker could edit. A
// checkout a few commits from production still compares when nothing deployed
// changed between them; that's settled here, as the exposed-file candidates
// depend on it.
func (r *run) hash(ctx context.Context) *audit.FileFacts {
	if r.tr.Hash == nil {
		r.problem("the hasher can't reach this site")
		return nil
	}
	start := time.Now()
	f, err := stream(ctx, func(ctx context.Context, w io.Writer) error { return r.tr.Hash(ctx, audit.Hasher, w) }, audit.ReadFiles)
	r.time("hasher", start)
	if err != nil {
		if ctx.Err() == nil {
			r.problem("the hasher failed: %v", err)
		}
		return nil
	}
	if r.t.Deployed != "" {
		f.Revision = r.t.Deployed
	}
	if r.repo != nil && f.Revision != "" && !strings.HasPrefix(r.repo.Revision, f.Revision) && audit.SameFiles(r.t.Repo, f.Revision) {
		r.mu.Lock()
		r.notes = append(r.notes, audit.Note{Group: audit.Files, Text: fmt.Sprintf("production runs %.12s, the checkout %.12s; nothing deployed changed between them, so files were compared", f.Revision, r.repo.Revision)})
		r.mu.Unlock()
		r.repo.Revision = f.Revision
	}
	return f
}

// where is the site's URLs: the collector's, else the last baseline's.
func (r *run) where(s *audit.SiteFacts) web.Target {
	if s != nil {
		return web.Target{Home: s.Home, Options: s.Options}
	}
	if b, err := r.o.Store.Baseline(r.t.Key()); err == nil && b != nil {
		return web.Target{Home: b.Home, Options: b.Options}
	}
	return web.Target{}
}

// merge joins the two probes' answers; nil when neither ran.
func merge(a, b *audit.WebFacts) *audit.WebFacts {
	if a == nil {
		return b
	}
	if b != nil {
		a.Base = cmp.Or(a.Base, b.Base)
		maps.Copy(a.Files, b.Files)
		maps.Copy(a.Listings, b.Listings)
		a.Sites = append(a.Sites, b.Sites...)
	}
	return a
}

// judge checks the facts and saves under the store's lock: the baseline
// when the run judged accounts and options, and the report with the last
// one's flags kept for the groups this run didn't judge.
func (r *run) judge(facts audit.Facts) (audit.Report, error) {
	st, k, cfg := *r.o.Store, r.t.Key(), *r.o.Config
	unlock, err := st.Lock()
	if err != nil {
		return audit.Report{}, err
	}
	defer unlock()
	prev, err := st.Baseline(k)
	if err != nil {
		return audit.Report{}, err
	}
	accepted, err := st.Accepted(k)
	if err != nil {
		return audit.Report{}, err
	}
	last, err := st.Report(k)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return audit.Report{}, err
	}
	pending := map[string]audit.Severity{}
	for _, f := range last.Flags {
		pending[f.ID] = f.Severity
	}
	var g audit.Geo
	path := cfg.GeoIP
	if path == "" {
		path = geo.DefaultPath()
	}
	if db, err := geo.Open(path); err == nil {
		defer db.Close()
		g = db
	}
	res := audit.Check(audit.Input{Facts: facts, Prev: prev, Repo: r.repo, Geo: g, Policy: audit.Policy{
		AllowedCountries: cfg.AllowedCountries, AllowedIPs: cfg.AllowedIPs,
		StaffDomains: cfg.StaffDomains, StaffEmails: cfg.StaffEmails,
		Skip: r.o.Skip, Accepted: accepted, Pending: pending,
	}})
	rep := res.Report
	rep.Notes = append(r.notes, rep.Notes...)
	if res.Baseline != nil {
		if err := st.SaveBaseline(k, res.Baseline); err != nil {
			return audit.Report{}, err
		}
	}
	if err := st.SaveReport(k, rep.Merge(last)); err != nil {
		return audit.Report{}, err
	}
	return rep, nil
}

// DeployedCommit is the commit of the checkout's repo's last successful
// production deploy run on GitHub (workflow deploy_production.yml), via gh;
// "" when it can't tell. The fleet deploys a built artifact, so the server
// has no REVISION file of its own.
func DeployedCommit(repo string) string {
	cmd := exec.Command("gh", "run", "list", "--workflow", "deploy_production.yml", "--status", "success",
		"--limit", "1", "--json", "headSha", "--jq", ".[0].headSha")
	cmd.Dir = repo
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	sha := strings.TrimSpace(string(out))
	if len(sha) != 40 {
		return ""
	}
	return sha
}

// SiteName is the origin repo's name, so worktrees share their checkout's
// state; the folder name when there's no origin.
func SiteName(repo string) string {
	if out, err := exec.Command("git", "-C", repo, "remote", "get-url", "origin").Output(); err == nil {
		u := strings.TrimSuffix(strings.TrimSpace(string(out)), ".git")
		if i := strings.LastIndexAny(u, "/:"); i >= 0 && i < len(u)-1 {
			return u[i+1:]
		}
	}
	abs, _ := filepath.Abs(repo)
	return filepath.Base(abs)
}
