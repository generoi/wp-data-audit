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
	"io"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	audit "github.com/generoi/wp-data-audit"
	"github.com/generoi/wp-data-audit/geo"
	"github.com/generoi/wp-data-audit/runner"
)

const usage = `usage:
  wp-data-audit [--env production] [--wp CMD] [--repo DIR] [--only|--skip CHECKS] [--json] [-v]
      audit the site, save a snapshot, print the flags (exit 1 if any).
      CHECKS: accounts, options, files, exposed, public, retention, content
      (comma-separated); skipping one also skips its remote work.
      --collector FILE, --hasher FILE: judge saved outputs (- for stdin)
  wp-data-audit script collector|hasher [--repo DIR] [--only|--skip CHECKS]
      print a script, to pipe to a site by hand:
      wp-data-audit script hasher | ssh host 'cd /site && sh -s' > hashed.txt
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
		case "script":
			return printScript(args[1:])
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

// checkFlags are the flags that choose what runs, shared by the audit and
// `script`.
func checkFlags(fs *flag.FlagSet) func() (map[string]bool, error) {
	only := fs.String("only", "", "run only these checks (comma-separated): "+strings.Join(audit.Groups, ", "))
	skip := fs.String("skip", "", "skip these checks (comma-separated)")
	return func() (map[string]bool, error) { return audit.ParseGroups(*only, *skip) }
}

// printScript is `script collector|hasher`: the script to pipe to a site by
// hand, e.g. `wp-data-audit script collector | ssh host wp eval-file -`.
func printScript(args []string) error {
	if len(args) == 0 || (args[0] != "collector" && args[0] != "hasher") {
		return errors.New("script: collector or hasher?")
	}
	fs, target := flags("script")
	groups := checkFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if args[0] == "hasher" {
		fmt.Print(audit.Hasher)
		return nil
	}
	t := target()
	var err error
	if t.Skip, err = groups(); err != nil {
		return err
	}
	r, err := runner.Prepare(t)
	if err != nil {
		return err
	}
	fmt.Print(r.Script)
	return nil
}

func auditSite(args []string) error {
	fs, target := flags("wp-data-audit")
	groups := checkFlags(fs)
	wp := fs.String("wp", "", "wp-cli command instead of vendor/bin/wp @<env>")
	shell := fs.String("sh", "", "command running a shell script from stdin on the site, instead of ssh to the alias's host (e.g. \"ddev exec sh -s\")")
	collectorIn := fs.String("collector", "", "judge this saved collector output instead of running it (- for stdin)")
	hasherIn := fs.String("hasher", "", "judge this saved hasher output instead of running it (- for stdin)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	verbose := fs.Bool("v", false, "print each phase's duration to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *collectorIn == "-" && *hasherIn == "-" {
		return errors.New("only one of --collector and --hasher can read stdin")
	}
	t := target()
	var err error
	if t.Skip, err = groups(); err != nil {
		return err
	}
	if t.Env == "production" {
		t.Deployed = runner.DeployedCommit(t.Repo)
	}
	// SIGINT, SIGTERM and SIGHUP stop the remote scripts and save nothing:
	// the last snapshot stays the baseline.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	r, err := runner.Prepare(t)
	if err != nil {
		return err
	}
	r.Context = ctx
	base := []string{"vendor/bin/wp", "@" + t.Env}
	if *wp != "" {
		base = strings.Fields(*wp)
	}
	// The hasher runs the server's own sh, find and sha256sum, never the
	// site's wp-cli: over ssh to the alias's host unless told otherwise.
	sh := strings.Fields(*shell)
	if len(sh) == 0 && *wp == "" && *hasherIn == "" && audit.NeedsHasher(t.Skip) {
		if sh, err = aliasSSH(t.Repo, t.Env); err != nil {
			fmt.Fprintln(os.Stderr, "wp-data-audit: hasher:", err)
		}
	}

	// The two scripts are independent: run them side by side.
	var out, hashed []byte
	var wg sync.WaitGroup
	if audit.NeedsCollector(t.Skip) {
		wg.Go(func() {
			start := time.Now()
			var err error
			if *collectorIn != "" {
				out, err = readInput(*collectorIn)
			} else {
				out, err = runWP(ctx, t.Repo, append(slices.Clone(base), audit.WPArgs...), r.Script)
			}
			r.Time("collector", start)
			if err != nil && ctx.Err() == nil { // the hasher needs no wp-cli: the files are still checked
				fmt.Fprintln(os.Stderr, "wp-data-audit: collector:", err)
				r.Note("the collector failed (" + err.Error() + "); the site's wp-cli may run the wrong PHP: set bin_path for the alias in wp-cli.yml to the folder of the right php (php_path only works where the release's vendor/bin/wp can execute)")
				out = nil
			}
		})
	}
	if audit.NeedsHasher(t.Skip) && (len(sh) > 0 || *hasherIn != "") {
		wg.Go(func() {
			start := time.Now()
			var err error
			if *hasherIn != "" {
				hashed, err = readInput(*hasherIn)
			} else {
				hashed, err = runWP(ctx, t.Repo, sh, r.Hasher)
			}
			r.Time("hasher", start)
			if err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "wp-data-audit: hasher:", err) // a note in the report; the rest still counts
				r.Note("the hasher failed: " + err.Error())
				hashed = nil
			}
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return fmt.Errorf("stopped by a signal: nothing saved")
	}
	if out == nil && hashed == nil && (audit.NeedsCollector(t.Skip) || audit.NeedsHasher(t.Skip)) {
		return errors.New("neither the collector nor the hasher ran")
	}
	start := time.Now()
	report, err := r.Finish(out, hashed)
	r.Time("finish (probes, judge, save)", start)
	if *verbose {
		for _, tm := range r.Timings {
			fmt.Fprintf(os.Stderr, "%8.1fs  %s\n", tm.Took.Seconds(), tm.Phase)
		}
		if snap, err := audit.Parse(out); err == nil && out != nil {
			for _, s := range slices.Sorted(maps.Keys(snap.Timings)) {
				fmt.Fprintf(os.Stderr, "%8.1fs    collector: %s\n", snap.Timings[s], s)
			}
		}
	}
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

// readInput is a saved script output: a file, or stdin for "-".
func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// runWP pipes script to argv in dir and returns its stdout. When ctx ends (a
// signal) the command gets SIGTERM, then SIGKILL after ten seconds: ssh then
// closes the session and the remote script ends with it.
func runWP(ctx context.Context, dir string, argv []string, script string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second
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
