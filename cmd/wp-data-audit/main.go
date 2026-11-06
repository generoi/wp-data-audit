// Command wp-data-audit runs the audit from a site's checkout over its wp-cli
// alias.
package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	audit "github.com/generoi/wp-data-audit"
	"github.com/generoi/wp-data-audit/geo"
	"github.com/generoi/wp-data-audit/runner"
)

const usage = `usage:
  wp-data-audit [--env production] [--wp CMD] [--repo DIR] [--json]
      audit the site, save a snapshot, print the flags (exit 1 if any)
  wp-data-audit accept --reason WHY [--everywhere] [--env production] [--repo DIR] ID...
      accept flags from the last audit; they stay quiet until what they describe changes.
      --everywhere: content flags (a script or iframe host) on every site
  wp-data-audit geoip-update
      download the DB-IP Lite country database

--wp replaces "vendor/bin/wp @<env>", e.g. --env local --wp "ddev wp".
Config: ~/.config/wp-data-audit/config.json; per site: data-audit.json in the repo.
State: ~/.local/state/wp-data-audit/<site>/<env>/.
`

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
			fs, t := flags("accept")
			reason := fs.String("reason", "", "why these are expected (required)")
			everywhere := fs.Bool("everywhere", false, "accept content flags on every site")
			if err := fs.Parse(args[1:]); err != nil {
				return err
			}
			if fs.NArg() == 0 {
				return errors.New("accept: which flag IDs?")
			}
			by := os.Getenv("USER")
			return runner.Accept(t(), fs.Args(), *reason, by, *everywhere)
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

// flags are the shared ones; the returned func gives the target after Parse.
func flags(name string) (*flag.FlagSet, func() runner.Target) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	env := fs.String("env", "production", "wp-cli alias without the @")
	repo := fs.String("repo", ".", "the site's checkout")
	return fs, func() runner.Target { return runner.Target{Site: runner.SiteName(*repo), Env: *env, Repo: *repo} }
}

func auditSite(args []string) error {
	fs, target := flags("wp-data-audit")
	wp := fs.String("wp", "", "wp-cli command instead of vendor/bin/wp @<env>")
	shell := fs.String("sh", "", "command running a shell script from stdin on the site, instead of ssh to the alias's host (e.g. \"ddev exec sh -s\")")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	t := target()
	if t.Env == "production" {
		t.Deployed = runner.DeployedCommit(t.Repo)
	}
	r, err := runner.Prepare(t)
	if err != nil {
		return err
	}
	base := []string{"vendor/bin/wp", "@" + t.Env}
	if *wp != "" {
		base = strings.Fields(*wp)
	}
	out, err := runWP(t.Repo, append(slices.Clone(base), audit.WPArgs...), r.Script)
	if err != nil { // the hasher needs no wp-cli: the files are still checked
		fmt.Fprintln(os.Stderr, "wp-data-audit: collector:", err)
		r.Note("the collector failed (" + err.Error() + "); the site's wp-cli may run the wrong PHP: set php_path for the alias in wp-cli.yml")
		out = nil
	}
	// The hasher runs the server's own sh, find and sha256sum, never the
	// site's wp-cli: over ssh to the alias's host unless told otherwise.
	sh := strings.Fields(*shell)
	if len(sh) == 0 && *wp == "" {
		if sh, err = aliasSSH(t.Repo, t.Env); err != nil {
			fmt.Fprintln(os.Stderr, "wp-data-audit: hasher:", err)
		}
	}
	var hashed []byte
	if len(sh) > 0 {
		if hashed, err = runWP(t.Repo, sh, r.Hasher); err != nil {
			fmt.Fprintln(os.Stderr, "wp-data-audit: hasher:", err) // a note in the report; the rest still counts
			r.Note("the hasher failed: " + err.Error())
		}
	}
	if out == nil && hashed == nil {
		return errors.New("neither the collector nor the hasher ran")
	}
	report, err := r.Finish(out, hashed)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		fmt.Print(runner.Text(t.Site+" @"+t.Env, report))
		if len(report.Flags) > 0 {
			fmt.Println("\naccept expected ones with: wp-data-audit accept --reason \"why\" <id>...")
		}
	}
	if len(report.Flags) > 0 {
		return exitCode(1)
	}
	return nil
}

var sshRE = regexp.MustCompile(`^(?:([A-Za-z0-9._-]+)@)?([A-Za-z0-9.-]+)(?::(\d+))?(/[A-Za-z0-9._/-]*)?$`)

// aliasSSH is the ssh command for wp-cli.yml's @env alias
// (`ssh: user@host:port/path`), running `sh -s` in its path.
func aliasSSH(repo, env string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(repo, "wp-cli.yml"))
	if err != nil {
		return nil, err
	}
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		key := strings.Trim(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ":")), `'"`)
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			in = key == "@"+env
			continue
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ssh:"); in && ok {
			m := sshRE.FindStringSubmatch(strings.Trim(strings.TrimSpace(v), `'"`))
			if m == nil {
				return nil, fmt.Errorf("wp-cli.yml @%s ssh %q: not user@host:port/path", env, strings.TrimSpace(v))
			}
			argv := []string{"ssh", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=20"}
			if m[3] != "" {
				argv = append(argv, "-p", m[3])
			}
			host := m[2]
			if m[1] != "" {
				host = m[1] + "@" + host
			}
			return append(argv, host, "cd '"+cmp.Or(m[4], ".")+"' && "+audit.HasherCommand), nil
		}
	}
	return nil, fmt.Errorf("wp-cli.yml has no ssh for @%s", env)
}

// runWP pipes script to argv in dir and returns its stdout.
func runWP(dir string, argv []string, script string) ([]byte, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return out.Bytes(), nil
}
