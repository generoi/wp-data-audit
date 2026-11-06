// Command wp-data-audit runs the audit from a site's checkout over its wp-cli
// alias, and keeps snapshots and accepted flags per site and environment.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	audit "github.com/generoi/wp-data-audit"
	"github.com/generoi/wp-data-audit/geo"
)

const usage = `usage:
  wp-data-audit [--env production] [--wp CMD] [--repo DIR] [--json]
      audit the site, save a snapshot, print the flags (exit 1 if any)
  wp-data-audit accept [--env production] [--repo DIR] ID...
      accept flags from the last audit; they stay quiet until what they describe changes
  wp-data-audit geoip-update
      download the DB-IP Lite country database

--wp replaces "vendor/bin/wp @<env>", e.g. --env local --wp "ddev wp".
Config: ~/.config/wp-data-audit/config.json. State: ~/.local/state/wp-data-audit/<site>/<env>/.
`

type config struct {
	AllowedCountries []string              `json:"allowed_countries"`
	StaffDomains     []string              `json:"staff_domains"`
	GeoIP            string                `json:"geoip"`
	Sites            map[string]siteConfig `json:"sites"`
}

type siteConfig struct {
	ClientDomains    []string `json:"client_domains"`
	LowRoles         []string `json:"low_roles"`
	AllowedCountries []string `json:"allowed_countries"` // added to the global list
}

func main() {
	err := run(os.Args[1:])
	var exit exitCode
	switch {
	case errors.As(err, &exit):
		os.Exit(int(exit))
	case err != nil:
		fmt.Fprintln(os.Stderr, "wp-data-audit:", err)
		os.Exit(2)
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "accept":
			return accept(args[1:])
		case "geoip-update":
			path := geo.DefaultPath()
			if err := geo.Update(context.Background(), path); err != nil {
				return err
			}
			fmt.Println("wrote", path)
			return nil
		case "help", "-h", "--help":
			fmt.Print(usage)
			return nil
		}
	}
	return auditSite(args)
}

func flags(name string) (*flag.FlagSet, *string, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	env := fs.String("env", "production", "wp-cli alias without the @")
	repo := fs.String("repo", ".", "the site's checkout")
	return fs, env, repo
}

func auditSite(args []string) error {
	fs, env, repo := flags("wp-data-audit")
	wp := fs.String("wp", "", "wp-cli command instead of vendor/bin/wp @<env>")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	site := siteName(*repo)
	sc := cfg.Sites[site]
	dir := stateDir(site, *env)

	script, err := audit.Script(sc.LowRoles)
	if err != nil {
		return err
	}
	argv := []string{"vendor/bin/wp", "@" + *env}
	if *wp != "" {
		argv = strings.Fields(*wp)
	}
	argv = append(argv, "eval-file", "-")
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = *repo
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	snap, err := audit.Parse(out.Bytes())
	if err != nil {
		return err
	}

	prev, err := latest(dir)
	if err != nil {
		return err
	}
	var notes []string
	exp, err := audit.ExpectedFromRepo(*repo)
	if err != nil {
		notes = append(notes, "can't read what the repo deploys: "+err.Error())
		exp = nil
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
	accepted, err := readAccepted(dir)
	if err != nil {
		return err
	}
	report := audit.Check(prev, snap, audit.Site{
		AllowedCountries: append(append([]string{}, cfg.AllowedCountries...), sc.AllowedCountries...),
		StaffDomains:     cfg.StaffDomains,
		ClientDomains:    sc.ClientDomains,
		Accepted:         accepted,
	}, exp, g)
	report.Notes = append(notes, report.Notes...)

	stamp := snap.GeneratedAt.UTC().Format("20060102T150405Z")
	if err := writeJSON(filepath.Join(dir, "snapshots", stamp+".json"), snap); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "report.json"), report); err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		printReport(os.Stdout, site+" @"+*env, report)
	}
	if len(report.Flags) > 0 {
		return exitCode(1)
	}
	return nil
}

func printReport(w io.Writer, target string, r audit.Report) {
	urgent := r.Urgent()
	fmt.Fprintf(w, "%s: %d urgent, %d to review\n", target, urgent, len(r.Flags)-urgent)
	for _, f := range r.Flags {
		fmt.Fprintf(w, "\n%-7s %s\n        %s\n", strings.ToUpper(f.Severity), f.ID, f.Message)
		if f.Untrusted != "" {
			fmt.Fprintf(w, "        site data: %q\n", f.Untrusted)
		}
	}
	if len(r.Notes) > 0 {
		fmt.Fprintln(w, "\nnotes:")
		for _, n := range r.Notes {
			fmt.Fprintln(w, "- "+n)
		}
	}
	if len(r.Flags) > 0 {
		fmt.Fprintln(w, "\naccept expected ones with: wp-data-audit accept <id>...")
	}
}

func accept(args []string) error {
	fs, env, repo := flags("accept")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("accept: which flag IDs?")
	}
	dir := stateDir(siteName(*repo), *env)
	var last audit.Report
	if err := readJSON(filepath.Join(dir, "report.json"), &last); err != nil {
		return fmt.Errorf("no audit to accept from: %w", err)
	}
	accepted, err := readAccepted(dir)
	if err != nil {
		return err
	}
	for _, id := range fs.Args() {
		if !slices.ContainsFunc(last.Flags, func(f audit.Flag) bool { return f.ID == id }) {
			return fmt.Errorf("%s isn't a flag in the last audit", id)
		}
		accepted[id] = true
	}
	ids := slices.Sorted(func(yield func(string) bool) {
		for id := range accepted {
			if !yield(id) {
				return
			}
		}
	})
	return writeJSON(filepath.Join(dir, "accepted.json"), ids)
}

func readAccepted(dir string) (map[string]bool, error) {
	var ids []string
	if err := readJSON(filepath.Join(dir, "accepted.json"), &ids); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m, nil
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

// siteName is the origin repo's name, so worktrees share their checkout's
// state; the folder name without an origin.
func siteName(repo string) string {
	if out, err := exec.Command("git", "-C", repo, "remote", "get-url", "origin").Output(); err == nil {
		u := strings.TrimSuffix(strings.TrimSpace(string(out)), ".git")
		if i := strings.LastIndexAny(u, "/:"); i >= 0 && i < len(u)-1 {
			return u[i+1:]
		}
	}
	abs, _ := filepath.Abs(repo)
	return filepath.Base(abs)
}

func home(env, rel string) string {
	if d := os.Getenv(env); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, rel)
}

func stateDir(site, env string) string {
	return filepath.Join(home("XDG_STATE_HOME", ".local/state"), "wp-data-audit", site, env)
}

func loadConfig() (config, error) {
	var c config
	err := readJSON(filepath.Join(home("XDG_CONFIG_HOME", ".config"), "wp-data-audit", "config.json"), &c)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	return c, err
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

// writeJSON is owner-only: snapshots hold staff emails and login IPs.
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
