// Package store keeps the audit's state on disk: per site environment its
// baselines, last report and accepted flags, and the flags accepted on every
// site. Owner-only, as they hold staff emails and login IPs. Files are
// written atomically and every write holds one flock, so the CLI, foreman's
// page and a running audit never lose each other's changes.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	audit "github.com/generoi/wp-data-audit"
)

// KeepBaselines is how many baselines a site keeps: the newest is the next
// run's comparison, the rest a short history.
const KeepBaselines = 12

// Store is the state under Root.
type Store struct{ Root string }

// Key is one site environment.
type Key struct{ Site, Env string }

// Default is the store under $XDG_STATE_HOME (~/.local/state)/wp-data-audit.
func Default() Store {
	root := os.Getenv("XDG_STATE_HOME")
	if root == "" {
		h, _ := os.UserHomeDir()
		root = filepath.Join(h, ".local", "state")
	}
	return Store{Root: filepath.Join(root, "wp-data-audit")}
}

// Dir is k's folder.
func (s Store) Dir(k Key) string { return filepath.Join(s.Root, k.Site, k.Env) }

// Lock takes the store's lock until the returned func is called.
func (s Store) Lock() (func(), error) {
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.Root, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// Baseline is k's newest baseline, nil before the first full run.
func (s Store) Baseline(k Key) (*audit.Baseline, error) {
	files, err := s.baselines(k)
	if err != nil || len(files) == 0 {
		return nil, err
	}
	var b audit.Baseline
	if err := readJSON(files[len(files)-1], &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// SaveBaseline adds b as k's newest and drops all but the last KeepBaselines.
func (s Store) SaveBaseline(k Key, b *audit.Baseline) error {
	path := filepath.Join(s.Dir(k), "baselines", b.At.UTC().Format("20060102T150405Z")+".json")
	if err := writeJSON(path, b); err != nil {
		return err
	}
	files, err := s.baselines(k)
	if err != nil {
		return err
	}
	for len(files) > KeepBaselines {
		if err := os.Remove(files[0]); err != nil {
			return err
		}
		files = files[1:]
	}
	return nil
}

func (s Store) baselines(k Key) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(s.Dir(k), "baselines", "*.json"))
	slices.Sort(files)
	return files, err
}

// Report is k's last report; an error wrapping os.ErrNotExist before any.
func (s Store) Report(k Key) (audit.Report, error) {
	var r audit.Report
	err := readJSON(filepath.Join(s.Dir(k), "report.json"), &r)
	return r, err
}

// SaveReport replaces k's last report.
func (s Store) SaveReport(k Key, r audit.Report) error {
	return writeJSON(filepath.Join(s.Dir(k), "report.json"), r)
}

// Decision is an accepted flag and why: the reasons are what the next
// triage reads, so a site's audits get quieter and better explained.
type Decision struct {
	ID     string    `json:"id"`
	Reason string    `json:"reason"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
	Flag   string    `json:"flag"` // the flag's message and site data when accepted
}

// Decisions are k's accepted flags, then the ones accepted on every site.
func (s Store) Decisions(k Key) ([]Decision, error) {
	var all []Decision
	for _, path := range []string{s.accepted(k), s.everywhere()} {
		var list []Decision
		if err := readJSON(path, &list); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		all = append(all, list...)
	}
	return all, nil
}

// Accepted is the set of k's accepted flag IDs, everywhere's included.
func (s Store) Accepted(k Key) (map[string]bool, error) {
	ds, err := s.Decisions(k)
	out := map[string]bool{}
	for _, d := range ds {
		out[d.ID] = true
	}
	return out, err
}

// Accept records flags from k's last report as accepted: they stay quiet
// until what they describe changes. Only a person decides this, and says
// why. everywhere accepts content flags (a script or iframe host, an inline
// snippet) on every site, their IDs being the value's hash.
func (s Store) Accept(k Key, ids []string, reason, by string, everywhere bool) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("accept: say why (the reason is what the next audit's triage reads)")
	}
	unlock, err := s.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	last, err := s.Report(k)
	if err != nil {
		return fmt.Errorf("no audit to accept from: %w", err)
	}
	path := s.accepted(k)
	if everywhere {
		path = s.everywhere()
	}
	var list []Decision
	if err := readJSON(path, &list); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, id := range ids {
		i := slices.IndexFunc(last.Flags, func(f audit.Flag) bool { return f.ID == id })
		if i < 0 {
			return fmt.Errorf("%s isn't a flag in the last audit of %s @%s", id, k.Site, k.Env)
		}
		f := last.Flags[i]
		if everywhere && f.Kind != audit.KindContent {
			return fmt.Errorf("%s: only content flags can be accepted everywhere", id)
		}
		list = slices.DeleteFunc(list, func(d Decision) bool { return d.ID == id })
		list = append(list, Decision{ID: id, Reason: reason, By: by, At: time.Now().UTC(), Flag: f.Message + ": " + f.Untrusted})
	}
	slices.SortFunc(list, func(a, b Decision) int { return strings.Compare(a.ID, b.ID) })
	return writeJSON(path, list)
}

func (s Store) accepted(k Key) string { return filepath.Join(s.Dir(k), "accepted.json") }
func (s Store) everywhere() string    { return filepath.Join(s.Root, "accepted-everywhere.json") }

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

// writeJSON writes v to path atomically (a temp file, then a rename).
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
