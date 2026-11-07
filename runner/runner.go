// Package runner is one audit end to end around however the caller reaches
// the site: Prepare gives the PHP to pipe to `wp eval-file -`, Finish judges
// its output and saves the snapshot and report, Accept records a person's
// decision. The CLI and foreman share its config and state, so a flag
// accepted in one stays accepted in the other.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	audit "github.com/generoi/wp-data-audit"
	"github.com/generoi/wp-data-audit/geo"
)

// Config is ~/.config/wp-data-audit/config.json: what's true for every site.
// What's true for one site lives in its repo (audit.ReadRepo).
type Config struct {
	AllowedCountries []string `json:"allowed_countries"`
	AllowedIPs       []string `json:"allowed_ips"`
	StaffDomains     []string `json:"staff_domains"`
	GeoIP            string   `json:"geoip"` // default geo.DefaultPath()
}

// LoadConfig reads the config; none is an empty one.
func LoadConfig() (Config, error) {
	var c Config
	err := readJSON(filepath.Join(home("XDG_CONFIG_HOME", ".config"), "wp-data-audit", "config.json"), &c)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	return c, err
}

// Target is one site environment. State is kept per Site and Env; Repo is
// its checkout at the deployed commit. Deployed is that commit from outside
// the server (GitHub's last successful deploy run); it wins over a Deployer
// REVISION file there. Files are only compared when the checkout matches it.
type Target struct {
	Site, Env, Repo string
	Deployed        string
}

// Run is one audit between Prepare and Finish: pipe Script to the site's
// wp-cli with audit.WPArgs and Hasher to `sh -s` over SSH in the release,
// then Finish with both outputs.
type Run struct {
	Target
	Script, Hasher string
	// Client asks the site's public URLs about files that may be exposed
	// (audit.NewClient when nil). Only candidates are asked: none, no request.
	Client *http.Client
	repo   *audit.Repo
	notes          []string
}

// Prepare reads the repo and builds the script.
func Prepare(t Target) (*Run, error) {
	r := &Run{Target: t}
	repo, err := audit.ReadRepo(t.Repo)
	if err != nil {
		r.notes = append(r.notes, "can't read the repo, so plugins weren't compared and no role counts as public: "+err.Error())
	} else {
		r.repo = repo
	}
	var roles map[string][]string
	if repo != nil {
		roles = repo.PublicRoles
	}
	if r.Script, err = audit.Script(roles); err != nil {
		return nil, err
	}
	r.Hasher = audit.Hasher
	return r, nil
}

// Note adds a line to the report, such as why a script didn't run.
func (r *Run) Note(s string) { r.notes = append(r.notes, s) }

// Finish judges the collector's and hasher's output against the last
// snapshot, saves the new snapshot and the report, and returns the report.
// Either may be nil when it didn't run (say why with Note): without the
// collector only files are judged and the last snapshot stays the baseline.
func (r *Run) Finish(out, hashed []byte) (audit.Report, error) {
	snap := &audit.Snapshot{Version: 1, GeneratedAt: time.Now().UTC(), NoCollector: true}
	if out != nil {
		var err error
		if snap, err = audit.Parse(out); err != nil {
			return audit.Report{}, err
		}
	}
	if hashed == nil {
		// didn't run: the caller noted why
	} else if rel, err := audit.ParseRelease(hashed); err == nil {
		if r.Deployed != "" { // GitHub's word over a file on the server an attacker could edit
			rel.Revision = r.Deployed
		}
		snap.Release = rel
		if r.repo != nil && rel.Revision != "" && !strings.HasPrefix(r.repo.Revision, rel.Revision) && audit.SameFiles(r.Repo, rel.Revision) {
			r.notes = append(r.notes, fmt.Sprintf("production runs %.12s, the checkout %.12s; nothing deployed changed between them, so files were compared", rel.Revision, r.repo.Revision))
			r.repo.Revision = rel.Revision
		}
	} else {
		r.notes = append(r.notes, "hasher: "+err.Error())
	}
	unlock, err := lock()
	if err != nil {
		return audit.Report{}, err
	}
	defer unlock()
	cfg, err := LoadConfig()
	if err != nil {
		return audit.Report{}, err
	}
	dir := StateDir(r.Target)
	prev, err := latest(dir)
	if err != nil {
		return audit.Report{}, err
	}
	decisions, err := Decisions(r.Target)
	if err != nil {
		return audit.Report{}, err
	}
	accepted := map[string]bool{}
	for _, d := range decisions {
		accepted[d.ID] = true
	}
	pending := map[string]string{}
	if last, err := LastReport(r.Target); err == nil {
		for _, f := range last.Flags {
			pending[f.ID] = f.Severity
		}
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
	if rel := snap.Release; rel != nil {
		rel.Exposed = audit.Candidates(rel, r.repo)
		home, options := snap.Home, snap.Options
		if home == "" && prev != nil {
			home, options = prev.Home, prev.Options
		}
		base := audit.DocrootURL(home)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		rel.Exposed.Probe(ctx, r.Client, rel, base, audit.BlogURLs(base, options))
		cancel()
	}
	report := audit.Check(prev, snap, audit.Site{
		AllowedCountries: cfg.AllowedCountries,
		AllowedIPs:       cfg.AllowedIPs,
		StaffDomains:     cfg.StaffDomains,
		Accepted:         accepted,
		Pending:          pending,
	}, r.repo, g)
	report.Notes = append(slices.Clone(r.notes), report.Notes...)

	if !snap.NoCollector { // a partial run would make every account look new next time
		stamp := snap.GeneratedAt.UTC().Format("20060102T150405Z")
		if err := writeJSON(filepath.Join(dir, "snapshots", stamp+".json"), snap); err != nil {
			return audit.Report{}, err
		}
	}
	if err := writeJSON(filepath.Join(dir, "report.json"), report); err != nil {
		return audit.Report{}, err
	}
	return report, nil
}

// Decision is an accepted flag and why: the reasons are what the next
// triage reads, so a site's audits get quieter and better explained.
type Decision struct {
	ID     string    `json:"id"`
	Reason string    `json:"reason"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
	Flag   string    `json:"flag"` // the message when it was accepted
}

// Accept records flags from the last report as accepted: they stay quiet
// until what they describe changes. Only a person decides this; reason is
// required. everywhere accepts content flags (a script or iframe host, an
// inline snippet) on every site, since their IDs are the value's hash.
func Accept(t Target, ids []string, reason, by string, everywhere bool) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("accept: say why (the reason is what the next audit's triage reads)")
	}
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	last, err := LastReport(t)
	if err != nil {
		return fmt.Errorf("no audit to accept from: %w", err)
	}
	path := filepath.Join(StateDir(t), "accepted.json")
	if everywhere {
		path = everywherePath()
	}
	var list []Decision
	if err := readJSON(path, &list); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, id := range ids {
		i := slices.IndexFunc(last.Flags, func(f audit.Flag) bool { return f.ID == id })
		if i < 0 {
			return fmt.Errorf("%s isn't a flag in the last audit of %s @%s", id, t.Site, t.Env)
		}
		if everywhere && !strings.HasPrefix(id, "content:") {
			return fmt.Errorf("%s: only content flags can be accepted everywhere", id)
		}
		list = slices.DeleteFunc(list, func(d Decision) bool { return d.ID == id })
		list = append(list, Decision{ID: id, Reason: reason, By: by, At: time.Now().UTC(), Flag: last.Flags[i].Message + ": " + last.Flags[i].Untrusted})
	}
	slices.SortFunc(list, func(a, b Decision) int { return strings.Compare(a.ID, b.ID) })
	return writeJSON(path, list)
}

// Decisions are the target's accepted flags, then the ones accepted everywhere.
func Decisions(t Target) ([]Decision, error) {
	var all []Decision
	for _, path := range []string{filepath.Join(StateDir(t), "accepted.json"), everywherePath()} {
		var list []Decision
		if err := readJSON(path, &list); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		all = append(all, list...)
	}
	return all, nil
}

// lock serialises every write to the state (audits finishing, accepts from
// the CLI and from foreman's page), so no decision is lost to a race.
func lock() (func(), error) {
	path := filepath.Join(home("XDG_STATE_HOME", ".local/state"), "wp-data-audit", ".lock")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func everywherePath() string {
	return filepath.Join(home("XDG_STATE_HOME", ".local/state"), "wp-data-audit", "accepted-everywhere.json")
}

// Text is the report for people: one block per flag, site data quoted.
func Text(target string, r audit.Report) string {
	var b strings.Builder
	urgent := r.Urgent()
	fmt.Fprintf(&b, "%s: %d urgent, %d to review\n", target, urgent, len(r.Flags)-urgent)
	for _, f := range r.Flags {
		fmt.Fprintf(&b, "\n%-7s %s\n        %s\n", strings.ToUpper(f.Severity), f.ID, f.Message)
		if f.Untrusted != "" {
			fmt.Fprintf(&b, "        site data: %q\n", f.Untrusted)
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("\nnotes:\n")
		for _, n := range r.Notes {
			b.WriteString("- " + n + "\n")
		}
	}
	return b.String()
}

// LastReport is the report of the last audit.
func LastReport(t Target) (audit.Report, error) {
	var r audit.Report
	err := readJSON(filepath.Join(StateDir(t), "report.json"), &r)
	return r, err
}

// StateDir is where a target's snapshots, report and accepted flags live,
// owner-only: they hold staff emails and login IPs.
func StateDir(t Target) string {
	return filepath.Join(home("XDG_STATE_HOME", ".local/state"), "wp-data-audit", t.Site, t.Env)
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

// latest is the newest saved snapshot, nil before the first audit.
func latest(dir string) (*audit.Snapshot, error) {
	files, err := filepath.Glob(filepath.Join(dir, "snapshots", "*.json"))
	if err != nil || len(files) == 0 {
		return nil, err
	}
	slices.Sort(files)
	var s audit.Snapshot
	if err := readJSON(files[len(files)-1], &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func home(env, rel string) string {
	if d := os.Getenv(env); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, rel)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
