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
	"syscall"
	"time"

	audit "github.com/generoi/wp-data-audit"
	"github.com/generoi/wp-data-audit/geo"
	"github.com/generoi/wp-data-audit/runner"
	"github.com/generoi/wp-data-audit/store"
)

const usage = `usage:
  wp-data-audit [--env production] [--repo DIR] [--only|--skip CHECKS] [--json] [-v]
                [--wp CMD] [--sh CMD] [--collector FILE] [--hasher FILE]
      audit the site, print the flags (exit 1 if any).
      CHECKS: accounts, options, files, exposed, public, retention, content
      (comma-separated); skipping one also skips its remote work.
      --wp replaces "vendor/bin/wp @<env>", --sh the ssh to the alias's host
      (e.g. --env local --wp "ddev wp" --sh "ddev exec sh -s");
      --collector, --hasher judge saved outputs instead (- for stdin).
  wp-data-audit accept --reason WHY [--everywhere] [--env production] [--repo DIR] ID...
      accept flags from the last audit; they stay quiet until what they describe changes.
      --everywhere: content flags (a script or iframe host) on every site
  wp-data-audit script collector|hasher [--repo DIR] [--only|--skip CHECKS]
      print a script, to pipe to a site by hand:
      wp-data-audit script hasher | ssh host 'cd /site && sh -s' > hashed.txt
  wp-data-audit geoip-update
      download the DB-IP Lite country database

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
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "accept":
		return accept(args[1:])
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

func checkFlags(fs *flag.FlagSet) func() (audit.Skip, error) {
	only := fs.String("only", "", "run only these checks (comma-separated)")
	skip := fs.String("skip", "", "skip these checks (comma-separated)")
	return func() (audit.Skip, error) { return audit.ParseSkip(*only, *skip) }
}

func accept(args []string) error {
	fs, target := flags("accept")
	reason := fs.String("reason", "", "why these are expected (required)")
	everywhere := fs.Bool("everywhere", false, "accept content flags on every site")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("accept: which flag IDs?")
	}
	return store.Default().Accept(target().Key(), fs.Args(), *reason, os.Getenv("USER"), *everywhere)
}

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
	skip, err := groups()
	if err != nil {
		return err
	}
	s, err := runner.CollectorScript(target(), skip)
	if err != nil {
		return err
	}
	fmt.Print(s)
	return nil
}

func auditSite(args []string) error {
	fs, target := flags("wp-data-audit")
	groups := checkFlags(fs)
	wp := fs.String("wp", "", "wp-cli command instead of vendor/bin/wp @<env>")
	shell := fs.String("sh", "", "command running a shell script from stdin in the release, instead of ssh to the alias's host")
	collectorIn := fs.String("collector", "", "judge this saved collector output (- for stdin)")
	hasherIn := fs.String("hasher", "", "judge this saved hasher output (- for stdin)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	verbose := fs.Bool("v", false, "print each phase's duration to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *collectorIn == "-" && *hasherIn == "-" {
		return errors.New("only one of --collector and --hasher can read stdin")
	}
	t := target()
	skip, err := groups()
	if err != nil {
		return err
	}
	if t.Env == "production" {
		t.Deployed = runner.DeployedCommit(t.Repo)
	}
	tr := transport(t, *wp, *shell, *collectorIn, *hasherIn)
	// SIGINT, SIGTERM and SIGHUP stop the remote scripts; nothing is saved.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	res, err := runner.Run(ctx, t, tr, runner.Options{Skip: skip})
	if *verbose {
		for _, tm := range res.Timings {
			fmt.Fprintf(os.Stderr, "%8.1fs  %s\n", tm.Took.Seconds(), tm.Phase)
		}
		for _, s := range slices.Sorted(maps.Keys(res.Collector)) {
			fmt.Fprintf(os.Stderr, "%8.1fs    collector: %s\n", res.Collector[s], s)
		}
		for _, s := range slices.Sorted(maps.Keys(res.Hasher)) {
			fmt.Fprintf(os.Stderr, "%8.1fs    hasher: %s\n", res.Hasher[s], s)
		}
	}
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res.Report); err != nil {
			return err
		}
	} else {
		fmt.Print(res.Report.Text(t.Site + " @" + t.Env))
		if len(res.Report.Flags) > 0 {
			fmt.Println("\naccept expected ones with: wp-data-audit accept --reason \"why\" <id>...")
		}
	}
	if len(res.Report.Flags) > 0 {
		return exitCode(1)
	}
	return nil
}

// transport reaches t: saved outputs, the given commands, or the wp-cli
// alias (vendor/bin/wp @env) and an ssh to its host for the hasher.
func transport(t runner.Target, wp, shell, collectorIn, hasherIn string) runner.Transport {
	var tr runner.Transport
	switch {
	case collectorIn != "":
		tr.Collect = func(context.Context, string) ([]byte, error) { return readInput(collectorIn) }
	default:
		argv := []string{"vendor/bin/wp", "@" + t.Env}
		if wp != "" {
			argv = strings.Fields(wp)
		}
		argv = append(argv, audit.WPArgs...)
		tr.Collect = func(ctx context.Context, script string) ([]byte, error) {
			out, err := pipe(ctx, t.Repo, argv, script)
			if err != nil {
				err = fmt.Errorf("%w (if the site's wp-cli runs the wrong PHP, set bin_path for the alias in wp-cli.yml to the right php's folder: php_path only works where the release's vendor/bin/wp can execute)", err)
			}
			return out, err
		}
	}
	switch {
	case hasherIn != "":
		tr.Hash = func(context.Context, string) ([]byte, error) { return readInput(hasherIn) }
	case shell != "":
		argv := strings.Fields(shell)
		tr.Hash = func(ctx context.Context, script string) ([]byte, error) { return pipe(ctx, t.Repo, argv, script) }
	case wp == "":
		argv, err := aliasSSH(t.Repo, t.Env)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wp-data-audit: hasher:", err)
			break
		}
		tr.Hash = func(ctx context.Context, script string) ([]byte, error) { return pipe(ctx, t.Repo, argv, script) }
	}
	return tr
}

var sshRE = regexp.MustCompile(`^(?:([A-Za-z0-9._-]+)@)?([A-Za-z0-9.-]+)(?::(\d+))?(/[A-Za-z0-9._/-]*)?$`)

// aliasSSH is the ssh command for wp-cli.yml's @env alias
// (`ssh: user@host:port/path`), running the hasher in its path.
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

// pipe pipes script to argv in dir and returns its stdout. When ctx ends (a
// signal) the command gets SIGTERM, then SIGKILL after ten seconds: ssh then
// closes the session and the remote script ends with it.
func pipe(ctx context.Context, dir string, argv []string, script string) ([]byte, error) {
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
