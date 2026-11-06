// Command wp-data-audit runs the audit from a site's checkout over its wp-cli
// alias.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

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
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	t := target()
	r, err := runner.Prepare(t)
	if err != nil {
		return err
	}
	argv := []string{"vendor/bin/wp", "@" + t.Env}
	if *wp != "" {
		argv = strings.Fields(*wp)
	}
	argv = append(argv, "eval-file", "-")
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = t.Repo
	cmd.Stdin = strings.NewReader(r.Script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	report, err := r.Finish(out.Bytes())
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
