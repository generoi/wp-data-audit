package runner

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	audit "github.com/generoi/wp-data-audit"
)

// GH runs gh with args in the checkout dir (so {owner}/{repo} is its
// origin's) and returns its stdout. Options.GH replaces it in tests.
type GH func(ctx context.Context, dir string, args ...string) ([]byte, error)

func execGH(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "gh", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
	}
	return out, err
}

// github reads the checkout's repo's outside collaborators and deploy keys
// (both need admin on the repo). Read-only.
func github(ctx context.Context, gh GH, dir string) (*audit.GitHubAccess, error) {
	g := &audit.GitHubAccess{}
	out, err := gh(ctx, dir, "api", "--paginate", "repos/{owner}/{repo}/collaborators?affiliation=outside&per_page=100",
		"--jq", `.[] | [.login, .role_name] | @tsv`)
	if err != nil {
		return nil, fmt.Errorf("GitHub collaborators: %w", err)
	}
	for _, f := range tsv(out) {
		if len(f) == 2 {
			g.Outside = append(g.Outside, audit.Collaborator{Login: f[0], Permission: f[1]})
		}
	}
	out, err = gh(ctx, dir, "api", "--paginate", "repos/{owner}/{repo}/keys?per_page=100",
		"--jq", `.[] | [.id, .title, .read_only, .created_at, (.last_used // "")] | @tsv`)
	if err != nil {
		return nil, fmt.Errorf("GitHub deploy keys: %w", err)
	}
	for _, f := range tsv(out) {
		if len(f) != 5 {
			continue
		}
		id, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		g.Keys = append(g.Keys, audit.DeployKey{ID: id, Title: f[1], ReadOnly: f[2] == "true", Created: day(f[3]), LastUsed: day(f[4])})
	}
	return g, nil
}

// tsv splits jq's @tsv lines (tabs and newlines inside a field are escaped).
func tsv(out []byte) [][]string {
	var rows [][]string
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			rows = append(rows, strings.Split(line, "\t"))
		}
	}
	return rows
}

// day is an RFC 3339 time's date ("" stays "").
func day(t string) string {
	d, _, _ := strings.Cut(t, "T")
	return d
}
