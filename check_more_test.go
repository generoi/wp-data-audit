package audit

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

func want(t *testing.T, got map[string]Severity, flags map[string]Severity) {
	t.Helper()
	for id, s := range flags {
		if got[id] != s {
			t.Errorf("flag %s: %q, want %q (all: %v)", id, got[id], s, slices.Sorted(maps.Keys(got)))
		}
	}
}

func onlyKind(r Report, k Kind) map[string]Severity {
	out := map[string]Severity{}
	for _, f := range r.Flags {
		if f.Kind == k {
			out[f.ID] = f.Severity
		}
	}
	return out
}

// Installed but active nowhere: remove it. Activated and deactivated since
// the last audit, per site. wordpress.org's closed and stale plugins.
func TestPlugins(t *testing.T) {
	s := site0()
	s.InstalledPlugins = []string{"akismet", "hello.php", "woocommerce", "network-only"}
	s.ActivePlugins = map[string][]string{"1": {"woocommerce/woocommerce.php"}, "network": {"network-only/n.php"}}
	prev := &Baseline{Plugins: map[string][]string{"1": {"akismet/akismet.php"}, "network": {"network-only/n.php"}}}
	in := Input{Facts: Facts{At: now, Site: s, WPOrg: map[string]WPOrgPlugin{
		"gone":   {Closed: true, Reason: "Security Issue", ClosedDate: "2025-01-01"},
		"asked":  {Closed: true, Reason: "Author Request"},
		"old":    {LastUpdated: "2022-01-01"},
		"fresh":  {LastUpdated: "2026-10-01"},
		"broken": {Err: "timeout"},
	}}, Prev: prev}
	r := Check(in).Report
	got := onlyKind(r, KindPlugin)
	want(t, got, map[string]Severity{
		"plugin-inactive:akismet": Review, "plugin-inactive:hello.php": Review,
		"plugin-activated:1:woocommerce": Review, "plugin-deactivated:1:akismet": Review,
		"plugin-closed:gone": Urgent, "plugin-closed:asked": Review, "plugin-stale:old:2022-01-01": Review,
	})
	if len(got) != 7 {
		t.Errorf("plugin flags %v", slices.Sorted(maps.Keys(got)))
	}
	if !strings.Contains(noteTexts(r), "wordpress.org couldn't be asked about 1 plugin") {
		t.Errorf("notes: %s", noteTexts(r))
	}
	// A baseline from before plugins were collected: nothing is "new" against it.
	in.Prev = &Baseline{}
	for id := range onlyKind(Check(in).Report, KindPlugin) {
		if strings.HasPrefix(id, "plugin-activated") || strings.HasPrefix(id, "plugin-deactivated") {
			t.Errorf("an old baseline made %s", id)
		}
	}
}

// Sensitive options compare by hash (role definitions and payment settings
// urgent); a cron hook the last audit didn't see stays flagged until
// accepted, also once the next baseline has it.
func TestSensitiveAndCron(t *testing.T) {
	s := site0()
	s.Sensitive = map[string]string{"user_roles": "b", "template": "t", "2:woocommerce_stripe_settings": "s", "stylesheet": "new"}
	s.Cron = map[string][]string{"1": {"evil_hook", "wp_version_check"}, "3": {"brand_new_site_hook"}}
	prev := &Baseline{
		Options:   s.Options,
		Sensitive: map[string]string{"user_roles": "a", "template": "t", "stylesheet": "old"},
		Cron:      map[string][]string{"1": {"wp_version_check"}},
	}
	r := Check(Input{Facts: Facts{At: now, Site: s}, Prev: prev})
	got := ids(r.Report)
	want(t, got, map[string]Severity{
		"sensitive:user_roles:b": Urgent, "sensitive:2:woocommerce_stripe_settings:s": Urgent,
		"sensitive:stylesheet:new": Review, "cron:1:evil_hook": Review,
	})
	for id := range got {
		if strings.Contains(id, "template") || strings.Contains(id, "brand_new_site_hook") || strings.Contains(id, "wp_version_check") {
			t.Errorf("unchanged or a new site's: %s", id)
		}
	}
	for _, f := range r.Report.Flags {
		if f.Kind == KindOption && strings.Contains(f.Untrusted, "->") && strings.HasPrefix(f.ID, "sensitive:") {
			t.Errorf("a sensitive option's value shown: %+v", f)
		}
	}
	// Next month: the baseline has the hook, but it was never accepted.
	next := Check(Input{Facts: Facts{At: now, Site: s}, Prev: r.Baseline, Policy: Policy{Pending: ids(r.Report)}})
	if ids(next.Report)["cron:1:evil_hook"] == "" {
		t.Error("an unaccepted new hook went quiet once it was in the baseline")
	}
}

// GitHub's outside collaborators and write deploy keys; Kinsta users who
// aren't staff (or are leavers), site users outside the client's domains,
// and extra SFTP accounts.
func TestAccess(t *testing.T) {
	a := &AccessFacts{
		GitHub: &GitHubAccess{
			Outside: []Collaborator{{Login: "contractor", Permission: "write"}},
			Keys:    []DeployKey{{ID: 1, Title: "ci", ReadOnly: true}, {ID: 2, Title: "server", Created: "2024-01-01"}},
		},
		Kinsta: &KinstaAccess{
			Users: []KinstaUser{
				{Email: "a@staff.example", Role: "company-admin", Scope: "company"},
				{Email: "left@staff.example", Role: "company-developer", Scope: "company"},
				{Email: "dev@agency-two.example", Role: "company-developer", Scope: "company"},
				{Email: "editor@client.example", Role: "site-admin", Scope: "site"},
				{Email: "someone@elsewhere.example", Role: "site-admin", Scope: "site"},
			},
			SFTP: []SFTPAccount{{Env: "live", Username: "uploader", Root: "/", Active: true, Permission: "write"}},
		},
	}
	in := Input{Facts: Facts{At: now, Access: a}, Repo: &Repo{ClientDomains: []string{"client.example"}},
		Policy: Policy{StaffDomains: []string{"staff.example"}, StaffEmails: []string{"a@staff.example"}}}
	got := ids(Check(in).Report)
	want(t, got, map[string]Severity{
		"collaborator:contractor:write": Review, "deploy-key:2": Review,
		"kinsta-user:left@staff.example:company-developer":     Review,
		"kinsta-user:dev@agency-two.example:company-developer": Review,
		"kinsta-user:someone@elsewhere.example:site-admin":     Review,
		"sftp:live:uploader:write":                             Review,
	})
	if len(got) != 6 {
		t.Errorf("access flags %v", slices.Sorted(maps.Keys(got)))
	}
	a.Kinsta = nil
	if r := Check(in).Report; !strings.Contains(noteTexts(r), "Kinsta users and SFTP accounts not checked") {
		t.Errorf("notes: %s", noteTexts(r))
	}
}
