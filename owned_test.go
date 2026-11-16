package audit

import (
	"strings"
	"testing"
)

const wpmlFile = "sitepress-multilingual-cms/sitepress.php"

// WPML's translator capabilities aren't injection while WPML is active; the
// rest of a user's extra capabilities still are, and so are WPML's names with
// WPML inactive.
func TestPluginOwnedCaps(t *testing.T) {
	s := site0()
	s.ActivePlugins = map[string][]string{"1": {wpmlFile}}
	s.Users = append(s.Users,
		User{ID: 20, Login: "tr", Roles: []string{"editor"}, ExtraCaps: []string{"translate", "manage_translations", "wpml_manage_languages"}},
		User{ID: 21, Login: "mixed", Roles: []string{"editor"}, ExtraCaps: []string{"translate", "manage_options"}})
	r := Check(Input{Facts: Facts{At: now, Site: s}}).Report
	caps := kind(r, KindCapabilities)
	if len(caps) != 1 || !strings.HasPrefix(caps[0].ID, "caps:21:") || strings.Contains(caps[0].Untrusted, "translate") {
		t.Fatalf("capability flags %+v", caps)
	}
	if !strings.Contains(noteTexts(r), "2 users hold capabilities that active plugins give") {
		t.Errorf("notes %s", noteTexts(r))
	}
	s.ActivePlugins = nil
	if n := len(kind(Check(Input{Facts: Facts{At: now, Site: s}}).Report, KindCapabilities)); n != 2 {
		t.Errorf("WPML inactive: %d capability flags, want 2", n)
	}
}

// A new hook with an active plugin's prefix is the plugin's own; the same
// hook without the plugin active is flagged.
func TestPluginOwnedCron(t *testing.T) {
	s := site0()
	s.ActivePlugins = map[string][]string{"1": {"wordpress-seo/wp-seo.php"}}
	s.Cron = map[string][]string{"1": {"wpseo_indexable_index_batch", "evil_hook"}}
	prev := &Baseline{Options: s.Options, Cron: map[string][]string{"1": {}}}
	r := Check(Input{Facts: Facts{At: now, Site: s}, Prev: prev}).Report
	got := ids(r)
	if got["cron:1:evil_hook"] != Review || got["cron:1:wpseo_indexable_index_batch"] != "" {
		t.Fatalf("cron flags %v", got)
	}
	if !strings.Contains(noteTexts(r), "1 new scheduled hooks belong to active plugins") {
		t.Errorf("notes %s", noteTexts(r))
	}
	s.ActivePlugins = nil
	if ids(Check(Input{Facts: Facts{At: now, Site: s}, Prev: prev}).Report)["cron:1:wpseo_indexable_index_batch"] != Review {
		t.Error("a wpseo_ hook with Yoast inactive went unflagged")
	}
}

// WPML's Twig cache under uploads is counted while WPML is active, only in
// its exact shape; anything else there stays urgent.
func TestPluginOwnedUploadsPHP(t *testing.T) {
	hash := strings.Repeat("6a", 32)
	f := files("", map[string]string{
		"web/app/uploads/cache/wpml/twig/6a/" + hash + ".php": "aaaa",
		"web/app/uploads/cache/wpml/twig/00/" + hash + ".php": "bbbb", // folder isn't its name's start
		"web/app/uploads/cache/wpml/twig/6a/shell.php":        "cccc",
	})
	s := site0()
	s.ActivePlugins = map[string][]string{"1": {wpmlFile}}
	r := Check(Input{Facts: Facts{At: now, Site: s, Files: f}, Repo: &Repo{LocalWhy: "no install"}}).Report
	var flagged []string
	for _, fl := range kind(r, KindFile) {
		if strings.HasPrefix(fl.ID, "upload-php:") {
			flagged = append(flagged, fl.Untrusted)
		}
	}
	if len(flagged) != 2 || strings.Contains(strings.Join(flagged, " "), "/6a/"+hash) {
		t.Fatalf("upload-php flags %v", flagged)
	}
	if !strings.Contains(noteTexts(r), "1 PHP files under uploads are sitepress-multilingual-cms's compiled cache") {
		t.Errorf("notes %s", noteTexts(r))
	}
	s.ActivePlugins = nil
	n := 0
	for _, fl := range kind(Check(Input{Facts: Facts{At: now, Site: s, Files: f}, Repo: &Repo{LocalWhy: "no install"}}).Report, KindFile) {
		if strings.HasPrefix(fl.ID, "upload-php:") {
			n++
		}
	}
	if n != 3 {
		t.Errorf("WPML inactive: %d upload-php flags, want 3", n)
	}
}

// A downloadable document a published page links to is counted; unlinked, or
// linked with a name that suggests people's data, it's still flagged.
func TestExposedLinkedDocuments(t *testing.T) {
	f := &FileFacts{Content: "web/app", Data: []DataFile{
		{Path: "web/app/uploads/brochure.pdf", Size: 1, Mtime: 1},
		{Path: "web/app/uploads/sites/2/price list.pdf", Size: 2, Mtime: 2},
		{Path: "web/app/uploads/stray.pdf", Size: 3, Mtime: 3},
		{Path: "web/app/uploads/customers-2019.pdf", Size: 4, Mtime: 4},
	}}
	served := map[string]Answer{}
	for _, d := range f.Data {
		served[d.Path] = Answer{Status: 200, Type: "application/pdf"}
	}
	s := site0()
	s.LinkedUploads = []string{"brochure.pdf", "sites/2/price list.pdf", "customers-2019.pdf"}
	r := Check(Input{Facts: Facts{At: now, Site: s, Files: f, Web: &WebFacts{Base: "https://site.example", Files: served}}}).Report
	got := map[string]bool{}
	for _, fl := range kind(r, KindExposed) {
		got[strings.SplitN(fl.Untrusted, " (", 2)[0]] = true
	}
	if !got["web/app/uploads/stray.pdf"] || !got["web/app/uploads/customers-2019.pdf"] || got["web/app/uploads/brochure.pdf"] || got["web/app/uploads/sites/2/price list.pdf"] {
		t.Fatalf("exposed flags %v", got)
	}
	if !strings.Contains(noteTexts(r), "2 downloadable documents under uploads that published pages link to") {
		t.Errorf("notes %s", noteTexts(r))
	}
}
