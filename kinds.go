package audit

import (
	"fmt"
	"slices"
	"strings"
)

// Severity is how soon a flag needs a person: Urgent is worth a ping now,
// Review goes in the maintenance report.
type Severity string

const (
	Urgent Severity = "urgent"
	Review Severity = "review"
)

func sev(urgent bool) Severity {
	if urgent {
		return Urgent
	}
	return Review
}

// Group is a set of checks run or skipped together (--only, --skip).
type Group string

const (
	Accounts  Group = "accounts"
	Options   Group = "options"
	Files     Group = "files"
	Exposed   Group = "exposed"
	Public    Group = "public"
	Retention Group = "retention"
	Content   Group = "content"
)

// Groups are every group, in report order.
var Groups = []Group{Accounts, Options, Files, Exposed, Public, Retention, Content}

// Kind is what a flag is about. Every kind belongs to one group.
type Kind string

const (
	KindPublicRole   Kind = "role"
	KindRegistration Kind = "registration"
	KindUser         Kind = "user"
	KindCapabilities Kind = "capabilities"
	KindAppPassword  Kind = "app-password"
	KindSession      Kind = "session"
	KindWooKey       Kind = "woo-key"
	KindDormant      Kind = "dormant"
	KindLeaver       Kind = "leaver"
	KindOption       Kind = "option"
	KindFile         Kind = "file"
	KindRelease      Kind = "release"
	KindChecksum     Kind = "checksum"
	KindExposed      Kind = "exposed"
	KindPublic       Kind = "public"
	KindRetention    Kind = "retention"
	KindContent      Kind = "content"
)

var kindGroup = map[Kind]Group{
	KindPublicRole: Accounts, KindRegistration: Accounts, KindUser: Accounts, KindCapabilities: Accounts,
	KindAppPassword: Accounts, KindSession: Accounts, KindWooKey: Accounts, KindDormant: Accounts, KindLeaver: Accounts,
	KindOption:  Options,
	KindFile:    Files, KindRelease: Files, KindChecksum: Files,
	KindExposed: Exposed, KindPublic: Public, KindRetention: Retention, KindContent: Content,
}

// Group is the group k belongs to.
func (k Kind) Group() Group { return kindGroup[k] }

// Skip is the set of groups not to run.
type Skip map[Group]bool

// ParseSkip turns --only and --skip (comma-separated group names) into the
// groups not to run.
func ParseSkip(only, skip string) (Skip, error) {
	parse := func(s string) ([]Group, error) {
		var out []Group
		for _, name := range strings.Split(s, ",") {
			g := Group(strings.TrimSpace(name))
			if g == "" {
				continue
			}
			if !slices.Contains(Groups, g) {
				return nil, fmt.Errorf("unknown check %q: want %s", g, joinGroups(Groups))
			}
			out = append(out, g)
		}
		return out, nil
	}
	s := Skip{}
	if only != "" {
		keep, err := parse(only)
		if err != nil {
			return nil, err
		}
		for _, g := range Groups {
			s[g] = !slices.Contains(keep, g)
		}
	}
	drop, err := parse(skip)
	if err != nil {
		return nil, err
	}
	for _, g := range drop {
		s[g] = true
	}
	return s, nil
}

// Runs reports whether g isn't skipped.
func (s Skip) Runs(g Group) bool { return !s[g] }

// Needs says which sources the groups that run need: the collector (the
// database), the hasher (the release's files) and the web probes.
func (s Skip) Needs() (collector, hasher, web bool) {
	collector = s.Runs(Accounts) || s.Runs(Options) || s.Runs(Retention) || s.Runs(Content)
	hasher = s.Runs(Files) || s.Runs(Exposed)
	web = s.Runs(Exposed) || s.Runs(Public)
	return
}

func joinGroups(gs []Group) string {
	var s []string
	for _, g := range gs {
		s = append(s, string(g))
	}
	return strings.Join(s, ", ")
}
