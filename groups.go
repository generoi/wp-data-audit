package audit

import (
	"fmt"
	"slices"
	"strings"
)

// Groups are the checks that can be run or skipped by name (--only, --skip).
var Groups = []string{"accounts", "options", "files", "exposed", "public", "retention", "content"}

// ParseGroups turns --only and --skip (comma-separated group names) into the
// set of skipped groups.
func ParseGroups(only, skip string) (map[string]bool, error) {
	parse := func(s string) ([]string, error) {
		var out []string
		for _, g := range strings.Split(s, ",") {
			if g = strings.TrimSpace(g); g == "" {
				continue
			}
			if !slices.Contains(Groups, g) {
				return nil, fmt.Errorf("unknown check %q: want %s", g, strings.Join(Groups, ", "))
			}
			out = append(out, g)
		}
		return out, nil
	}
	skipped := map[string]bool{}
	if only != "" {
		keep, err := parse(only)
		if err != nil {
			return nil, err
		}
		for _, g := range Groups {
			skipped[g] = !slices.Contains(keep, g)
		}
	}
	drop, err := parse(skip)
	if err != nil {
		return nil, err
	}
	for _, g := range drop {
		skipped[g] = true
	}
	return skipped, nil
}

// GroupOf is the check group a flag's Kind belongs to.
func GroupOf(kind string) string {
	switch kind {
	case "role", "registration", "user", "capabilities", "app-password", "session", "woo-key", "dormant", "leaver":
		return "accounts"
	case "option":
		return "options"
	case "file", "release", "checksum":
		return "files"
	case "exposed", "public", "retention", "content":
		return kind
	}
	return ""
}

// NeedsCollector: a group that reads the database runs. public reuses the
// last snapshot's URLs when the collector doesn't run.
func NeedsCollector(skip map[string]bool) bool {
	return !skip["accounts"] || !skip["options"] || !skip["retention"] || !skip["content"]
}

// NeedsHasher: a group that lists the release's files runs.
func NeedsHasher(skip map[string]bool) bool {
	return !skip["files"] || !skip["exposed"]
}
