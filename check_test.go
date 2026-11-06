package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type fakeGeo map[string]string

func (g fakeGeo) Country(ip string) string { return g[ip] }

func ids(r Report) map[string]string {
	m := map[string]string{}
	for _, f := range r.Flags {
		m[f.ID] = f.Severity
	}
	return m
}

func base0() *Snapshot {
	return &Snapshot{
		Version: 1,
		Options: map[string]string{"siteurl": "https://site.example/wp", "home": "https://site.example", "admin_email": "admin@staff.example"},
		Users: []User{{
			ID: 1, Login: "admin", Email: "admin@staff.example", Roles: []string{"administrator"}, Privileged: true,
			Sessions: []Session{{IP: "203.0.113.1"}, {IP: "203.0.113.2"}},
		}},
	}
}

func TestFirstRunFlagsForReviewThenAcceptSilences(t *testing.T) {
	site := Site{StaffDomains: []string{"staff.example"}, AllowedCountries: []string{"FI"}, Accepted: map[string]bool{}}
	geo := fakeGeo{"203.0.113.1": "FI", "203.0.113.2": "XX"}
	r := Check(nil, base0(), site, nil, geo)
	got := ids(r)
	if len(got) != 2 {
		t.Fatalf("flags %v, want the admin and one session", r.Flags)
	}
	for id, sev := range got {
		if sev != Review {
			t.Errorf("%s is %s on a first run, want review", id, sev)
		}
		site.Accepted[id] = true
	}
	if r := Check(base0(), base0(), site, nil, geo); len(r.Flags) != 0 {
		t.Fatalf("accepted flags came back: %v", r.Flags)
	}
}

func TestNewAdminOutsideDomainsIsUrgent(t *testing.T) {
	cur := base0()
	cur.Users = append(cur.Users, User{ID: 7, Login: "x", Email: "x@mail.example", Roles: []string{"administrator"}, Privileged: true})
	r := Check(base0(), cur, Site{StaffDomains: []string{"staff.example"}}, nil, nil)
	for _, f := range r.Flags {
		if strings.HasPrefix(f.ID, "user:7:") {
			if f.Severity != Urgent || !strings.Contains(f.Message, "outside") {
				t.Fatalf("new admin flag %+v", f)
			}
			return
		}
	}
	t.Fatalf("no flag for the new admin: %v", r.Flags)
}

func TestRoleChangeChangesID(t *testing.T) {
	prev := base0()
	prev.Users[0].Roles = []string{"editor"}
	site := Site{Accepted: map[string]bool{}}
	for id := range ids(Check(nil, prev, site, nil, nil)) {
		site.Accepted[id] = true
	}
	r := Check(prev, base0(), site, nil, nil)
	if len(r.Flags) != 1 || r.Flags[0].Severity != Urgent {
		t.Fatalf("editor promoted to admin: %v", r.Flags)
	}
}

func TestUrgentSignals(t *testing.T) {
	cur := base0()
	cur.Options["siteurl"] = "https://evil.example"
	cur.Users = append(cur.Users, User{ID: 9, Login: "c", Roles: []string{"customer"}, ExtraCaps: []string{"manage_options"}})
	cur.Registration = Registration{Open: true, Role: "editor", RoleCaps: []string{"read", "edit_posts"}}
	cur.Files = Files{
		UploadsPHP: []File{{Path: "2024/01/x.php", SHA256: "abcdef0123456789"}, {Path: "index.php", Silence: true}},
		Plugins:    []string{"akismet", "evil"},
		MuPlugins:  []string{"kinsta-mu-plugins", "ours.php", "dropped.php"},
		Dropins:    []string{"object-cache.php"},
	}
	cur.Checksums = Checksums{
		Core:    []string{"Warning: File doesn't verify against checksum: wp-includes/x.php"},
		Plugins: []PluginChecksum{{Plugin: "akismet", File: "a.php"}, {Plugin: "patched", File: "b.php"}},
	}
	cur.Content = []Match{
		{Kind: "script-src", Hash: "h1", Snippet: "tags.example", Count: 2, At: []Location{{Table: "posts", ID: 3, Field: "post_content"}, {Table: "options", Key: "widget"}}},
		{Kind: "script-inline", Hash: "h2", Encoded: true, Count: 1, At: []Location{{Table: "posts", ID: 4, Field: "post_content"}}},
	}
	exp := &Expected{
		Plugins: map[string]bool{"akismet": true}, MuPlugins: map[string]bool{"ours.php": true},
		Dropins: map[string]bool{}, PatchedPlugins: map[string]bool{"patched": true},
	}
	got := ids(Check(base0(), cur, Site{}, exp, nil))
	want := map[string]string{
		"option:siteurl:" + short("https://evil.example"): Urgent,
		"caps:9:" + short("manage_options"):               Urgent,
		"registration:editor":                              Urgent,
		"upload-php:2024/01/x.php:abcdef012345":            Urgent,
		"plugin:evil":                                      Urgent,
		"mu-plugin:dropped.php":                            Urgent,
		"dropin:object-cache.php":                          Urgent,
		"plugin-checksum:akismet:a.php":                    Urgent,
		"content:h1":                                       Review,
		"content:h2":                                       Urgent,
	}
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("%s: got %q, want %q", id, got[id], sev)
		}
	}
	for id := range got {
		if strings.HasPrefix(id, "plugin-checksum:patched") || strings.Contains(id, "kinsta") || id == "upload-php:index.php:" {
			t.Errorf("unexpected flag %s", id)
		}
	}
}

func TestExpectedFromRepo(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("composer.json", `{"extra":{"installer-paths":{
		"web/app/mu-plugins/{$name}/":["type:wordpress-muplugin","wp-plugin/moved"],
		"web/app/plugins/{$name}/":["type:wordpress-plugin"]},
		"patches":{"wp-plugin/fixed":{},"roots/wordpress-no-content":{}}}}`)
	write("composer.lock", `{"packages":[
		{"name":"wp-plugin/fixed","type":"wordpress-plugin"},
		{"name":"wp-plugin/moved","type":"wordpress-plugin"},
		{"name":"vendor/mu","type":"wordpress-muplugin"},
		{"name":"vendor/lib","type":"library"}],
		"packages-dev":[{"name":"wp-plugin/dev-only","type":"wordpress-plugin"}]}`)
	write("web/app/mu-plugins/local.php", "<?php")
	write("web/app/plugins/custom/custom.php", "<?php")
	write("web/app/object-cache.php", "<?php")
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	exp, err := ExpectedFromRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, set map[string]bool, want ...string) {
		t.Helper()
		if len(set) != len(want) {
			t.Errorf("%s: %v, want %v", name, set, want)
		}
		for _, w := range want {
			if !set[w] {
				t.Errorf("%s: missing %s in %v", name, w, set)
			}
		}
	}
	check("plugins", exp.Plugins, "fixed", "custom")
	check("mu-plugins", exp.MuPlugins, "moved", "mu", "local.php")
	check("dropins", exp.Dropins, "object-cache.php")
	check("patched", exp.PatchedPlugins, "fixed")
	if !exp.PatchedCore {
		t.Error("core patch not seen")
	}
}

func TestScriptAndParse(t *testing.T) {
	s, err := Script([]string{"member"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "<?php\n$wpda_low_roles = ['subscriber', 'customer', 'member'];\n") {
		t.Fatalf("script head: %.120s", s)
	}
	if _, err := Script([]string{"x'];system('id');//"}); err == nil {
		t.Fatal("a role with quotes went into the script")
	}
	if php, err := exec.LookPath("php"); err == nil {
		f := filepath.Join(t.TempDir(), "c.php")
		os.WriteFile(f, []byte(s), 0o644)
		if out, err := exec.Command(php, "-l", f).CombinedOutput(); err != nil {
			t.Fatalf("php -l: %s", out)
		}
	}
	snap, err := Parse([]byte("Notice: noise\n\nWPDA-BEGIN\n{\"version\":1,\"role_counts\":{\"customer\":3}}\nWPDA-END\n"))
	if err != nil || snap.RoleCounts["customer"] != 3 {
		t.Fatalf("parse: %v %+v", err, snap)
	}
	if _, err := Parse([]byte("\nWPDA-BEGIN\n{\"version\":1")); err == nil {
		t.Fatal("parsed output that was cut short")
	}
}
