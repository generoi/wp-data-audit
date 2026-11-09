package audit

import (
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
)

// MaxCandidates caps the files whose public URL is asked about.
const MaxCandidates = 300

// Candidate is a file a web server may hand out that shouldn't be public.
type Candidate struct {
	DataFile
	Type  string // dump, secret, repo, backup, archive, log, document
	Why   string
	Media bool // a media library upload: public on purpose, only its name is odd
}

var (
	typeRE = []struct {
		typ string
		re  *regexp.Regexp
	}{
		{"repo", regexp.MustCompile(`(^|/)\.git/config$`)},
		{"dump", regexp.MustCompile(`(?i)\.(sql(\..+)?|dump|sqlite3?|db|mdb|wpress)$`)},
		{"secret", regexp.MustCompile(`(?i)((^|/)\.env(\..*)?|\.env|\.key|\.pem|\.p12|\.pfx)$`)},
		{"log", regexp.MustCompile(`(?i)\.log$`)},
		{"archive", regexp.MustCompile(`(?i)\.(zip|tar(\..+)?|tgz|7z|rar)$`)},
		{"backup", regexp.MustCompile(`(?i)(\.(bak|backup|old|orig|save|swp)|~|(^|/)wp-config[^/]*)$`)},
	}
	typeRank = map[string]int{"dump": 0, "secret": 1, "repo": 2, "backup": 3, "archive": 4, "document": 5, "log": 6}

	mediaRE = regexp.MustCompile(`^(sites/\d+/)?\d{4}/\d{2}/`)
	// Gravity Forms' entry uploads: gravity_forms/<form id>-<wp_hash>/, its
	// YYYY/MM/ and tmp/. Not its export/ (entry CSVs an interrupted export
	// leaves behind) or logs/ (debug logs, often with entry data).
	formsRE  = regexp.MustCompile(`^(sites/\d+/)?gravity_forms/\d+-[0-9a-f]{32}/`)
	blogRE   = regexp.MustCompile(`^sites/(\d+)/`)
	tokensRE = regexp.MustCompile(`\p{L}+`)

	// Folders under uploads a plugin writes its own files to, and the plugin
	// folders that own them: its files there aren't flagged while it's active
	// on that site, and are once it's gone (left behind with nothing using them).
	// Complianz serves its consent vendor lists, CSS and proof-of-consent
	// PDFs to visitors; WP All Export's exports are kept public for feeds.
	pluginUploads = map[string][]string{
		"complianz":   {"complianz-gdpr", "complianz-gdpr-premium"},
		"wpallexport": {"wp-all-export-pro", "wp-all-export"},
		"wpallimport": {"wp-all-import-pro", "wp-all-import"},
	}

	// Words in a file name that suggest people's data, in English, Finnish
	// and Swedish: a word starting with one of personalStems, or one of
	// personalWords. Whole words only, so "User Guide", a surname like Hauser
	// and "order form" don't count; "users", "orders" and "asiakkaat" do.
	personalStems = []string{
		"asiaka", "asiakka", "customer", "member", "jasen", "jäsen", "medlem", "tilaus", "tilauks",
		"bestallning", "beställning", "export", "hakemu", "ansokan", "ansökan", "applicant",
		"invoice", "lasku", "faktur", "henkilö", "henkilo", "personuppgift", "kund", "backup",
		"varmuuskop", "dump", "gdpr", "newsletter", "uutiskirje", "subscriber", "contacts",
		"yhteystied", "kontakter", "sähköpost", "sahkopost", "osallistuj", "deltagar",
		"participant", "registration", "ilmoittautu", "anmälning", "anmalning", "userlist",
	}
	personalWords = map[string]bool{"cv": true, "users": true, "orders": true, "emails": true, "personal": true}
)

// personal: the file name has a word suggesting people's data.
func personal(name string) bool {
	for _, w := range tokensRE.FindAllString(strings.ToLower(name), -1) {
		if personalWords[w] || slices.ContainsFunc(personalStems, func(s string) bool { return strings.HasPrefix(w, s) }) {
			return true
		}
	}
	return false
}

func dataType(p string) string {
	for _, t := range typeRE {
		if t.re.MatchString(p) {
			return t.typ
		}
	}
	return "document"
}

// Candidates are the hasher's data files worth asking the public URL about:
// anything risky by type, and documents outside the media library (or in it
// under a name that suggests people's data). Files the checkout's install
// has at the same path are the release's own; with a checkout at another
// commit, the files git tracks at the deployed one are (Repo.Tracked), and
// what Composer installs (plugins, vendor) is only counted. notes say what
// was only counted. Pure and deterministic: the probes ask about these
// paths, and the exposed check joins their answers back to them.
func Candidates(f *FileFacts, repo *Repo) (out []Candidate, notes []string) {
	if f == nil {
		return nil, nil
	}
	uploads := f.Content + "/uploads/"
	compare := repo != nil && repo.Dir != "" && !stale(f, repo)
	var tracked map[string]bool
	if repo != nil && !compare && repo.TrackedAt != "" && f.Revision != "" && strings.HasPrefix(repo.TrackedAt, f.Revision) {
		tracked = repo.Tracked
	}
	var media, forms, unchecked, declared, jsons int
	var oldestForm int64
	for _, d := range f.Data {
		p, name := d.Path, path.Base(d.Path)
		if name == "wp-config.php" || name == "wp-config-sample.php" {
			continue
		}
		inUploads := strings.HasPrefix(p, uploads)
		if !inUploads {
			if compare {
				if repo.Has(p) {
					continue
				}
			} else if tracked[p] {
				continue
			} else if shipped(p, f.Content) {
				unchecked++
				continue
			}
		}
		t := dataType(p)
		rest := strings.TrimPrefix(p, uploads)
		doc := t == "document" || t == "archive"
		isMedia := inUploads && doc && mediaRE.MatchString(rest)
		why := ""
		switch {
		case !inUploads && t == "document":
			why = "outside the media library"
		case !inUploads:
			why = t + " in the docroot"
		case formsRE.MatchString(rest) && doc:
			forms++
			if oldestForm == 0 || d.Mtime < oldestForm {
				oldestForm = d.Mtime
			}
			continue
		case isMedia && !personal(name):
			media++
			continue
		case inUploads && doc && repo.publicUpload(rest):
			declared++
			continue
		case t == "document" && strings.HasSuffix(strings.ToLower(name), ".json") && !personal(name):
			jsons++ // plugins' own data and caches; an export with a telling name still counts
			continue
		case isMedia:
			why = "a media library upload whose name suggests people's data"
		case personal(name):
			why = "the name suggests people's data"
		case doc:
			why = "in a plugin's folder under uploads, not the media library"
		default:
			why = t + " under uploads"
		}
		out = append(out, Candidate{DataFile: d, Type: t, Why: why, Media: isMedia})
	}
	slices.SortStableFunc(out, func(a, b Candidate) int {
		if r := typeRank[a.Type] - typeRank[b.Type]; r != 0 {
			return r
		}
		return strings.Compare(a.Path, b.Path)
	})
	if n := len(out); n > MaxCandidates {
		notes = append(notes, fmt.Sprintf("%d more candidate files weren't checked (over %d)", n-MaxCandidates, MaxCandidates))
		out = out[:MaxCandidates]
	}
	for _, n := range []struct {
		count int
		text  string
	}{
		{media, "%d documents in the media library not checked: uploaded on purpose, no name suggests people's data"},
		{declared, "%d files in folders the repo's data-audit.json declares public not checked"},
		{jsons, "%d JSON files under uploads not checked: plugins' own data, no name suggests people's data"},
		{unchecked, "%d data files in plugins, themes and core not checked: no install of the deployed commit to tell the release's own from added ones"},
	} {
		if n.count > 0 {
			notes = append(notes, fmt.Sprintf(n.text, n.count))
		}
	}
	if forms > 0 {
		notes = append(notes, fmt.Sprintf("%d Gravity Forms uploads (public to anyone with the link), the oldest from %s: worth a retention policy", forms, day(oldestForm)))
	}
	return out, notes
}

// exposed: a file the public URL hands out is urgent (one flag per plugin
// folder under uploads), so is a listed folder; a risky file the server only
// keeps is for review; blocked logs and documents are only counted, and so
// are documents in an active plugin's own uploads folder (pluginUploads).
func (c *checker) exposed() {
	f, w := c.in.Facts.Files, c.in.Facts.Web
	cands, notes := Candidates(f, c.in.Repo)
	for _, n := range notes {
		c.info("%s", n)
	}
	uploads := f.Content + "/uploads/"
	blocked := map[string]int{}
	owned := map[string]int{}
	folders := map[string][]Candidate{}
	for _, cd := range cands {
		if p := c.uploadsOwner(cd.Path, uploads); p != "" && (cd.Type == "document" || cd.Type == "archive") {
			owned[p]++
			continue
		}
		a, asked := w.Files[cd.Path]
		at := fmt.Sprintf("%s (%d bytes, %s)", cd.Path, cd.Size, day(cd.Mtime))
		id := "exposed:" + idPart(cd.Path) + ":" + short(fmt.Sprint(cd.Size), fmt.Sprint(cd.Mtime))
		switch {
		case !asked:
			c.problem("%s wasn't asked about", cd.Path)
		case a.Served() && !cd.Media && pluginFolder(cd.Path, uploads) != "":
			g := pluginFolder(cd.Path, uploads)
			folders[g] = append(folders[g], cd)
		case a.Served() && cd.Media:
			c.flag(Flag{ID: id, Severity: Review, Kind: KindExposed,
				Message: cd.Type + " anyone can download (" + cd.Why + "): check it's meant to be public", Untrusted: at})
		case a.Served():
			c.flag(Flag{ID: id, Severity: Urgent, Kind: KindExposed, Message: cd.Type + " anyone can download (" + cd.Why + ")", Untrusted: at})
		case a.Status == 200 || a.Status == 206:
			c.flag(Flag{ID: id, Severity: Review, Kind: KindExposed,
				Message: cd.Type + ": its URL answers 200 with a web page, open it to check (" + cd.Why + ")", Untrusted: at})
		case a.Err != "":
			c.flag(Flag{ID: id, Severity: Review, Kind: KindExposed, Message: cd.Type + ": its public URL couldn't be checked: " + a.Err, Untrusted: at})
		case cd.Type == "log" || cd.Type == "document":
			blocked[cd.Type]++
		default:
			c.flag(Flag{ID: id, Severity: Review, Kind: KindExposed,
				Message: fmt.Sprintf("%s on the server, not served (HTTP %d): delete it if nothing needs it", cd.Type, a.Status), Untrusted: at})
		}
	}
	// One flag per plugin folder, its ID covering every file in it, so
	// accepting holds until any of them changes or a new one appears.
	for _, g := range slices.Sorted(maps.Keys(folders)) {
		fs := folders[g]
		var sig, list []string
		types := map[string]int{}
		for _, cd := range fs {
			sig = append(sig, cd.Path, fmt.Sprint(cd.Size), fmt.Sprint(cd.Mtime))
			types[cd.Type]++
			if len(list) < 20 {
				list = append(list, strings.TrimPrefix(cd.Path, g+"/"))
			}
		}
		if len(fs) > len(list) {
			list = append(list, fmt.Sprintf("… %d more", len(fs)-len(list)))
		}
		var what []string
		for _, t := range slices.Sorted(maps.Keys(types)) {
			what = append(what, fmt.Sprintf("%d %s", types[t], t))
		}
		c.flag(Flag{ID: "exposed:" + idPart(g) + ":" + short(sig...), Severity: Urgent, Kind: KindExposed,
			Message:   fmt.Sprintf("%d files anyone can download in a plugin's folder under uploads (%s)", len(fs), strings.Join(what, ", ")),
			Untrusted: g + ": " + strings.Join(list, ", ")})
	}
	for _, t := range slices.Sorted(maps.Keys(blocked)) {
		c.info("%d %ss on the server that the public URL doesn't serve", blocked[t], t)
	}
	for _, p := range slices.Sorted(maps.Keys(owned)) {
		c.info("%d files in %s's own uploads folder not checked: the plugin is active", owned[p], p)
	}
	for _, d := range slices.Sorted(maps.Keys(w.Listings)) {
		if l := w.Listings[d]; l.Listed {
			c.flag(Flag{ID: "listing:" + idPart(d), Severity: Urgent, Kind: KindExposed, Message: "the web server lists this folder's files", Untrusted: d})
		}
	}
}

// pluginFolder is the folder a served file is grouped under: the first two
// folders below uploads (and a multisite's sites/<id>/), e.g.
// web/app/uploads/wpallexport/exports; "" outside uploads or in its root.
func pluginFolder(p, uploads string) string {
	rest, ok := strings.CutPrefix(p, uploads)
	if !ok {
		return ""
	}
	prefix := ""
	if m := blogRE.FindString(rest); m != "" {
		prefix, rest = m, rest[len(m):]
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return ""
	}
	return uploads + prefix + strings.Join(parts[:min(2, len(parts)-1)], "/")
}

// uploadsOwner is the active plugin whose own uploads folder (pluginUploads)
// p is in, on that file's site or network-wide; "" when there's none or no
// collector ran to say which plugins are active.
func (c *checker) uploadsOwner(p, uploads string) string {
	s := c.in.Facts.Site
	rest, ok := strings.CutPrefix(p, uploads)
	if s == nil || !ok {
		return ""
	}
	blog := "1"
	if m := blogRE.FindStringSubmatch(rest); m != nil {
		blog, rest = m[1], rest[len(m[0]):]
	}
	dir, _, _ := strings.Cut(rest, "/")
	for _, f := range append(slices.Clone(s.ActivePlugins[blog]), s.ActivePlugins["network"]...) {
		if slices.Contains(pluginUploads[dir], pluginName(f)) {
			return pluginName(f)
		}
	}
	return ""
}

// shipped is a path a deploy writes: plugins, themes, mu-plugins, core, vendor.
func shipped(p, content string) bool {
	for _, d := range []string{content + "/plugins/", content + "/themes/", content + "/mu-plugins/", "web/wp/", "wp-includes/", "wp-admin/", "vendor/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// UploadsBlog is the multisite blog id an uploads path belongs to
// (uploads/sites/<id>/), "" for the main site's.
func UploadsBlog(p, content string) string {
	if m := blogRE.FindStringSubmatch(strings.TrimPrefix(p, content+"/uploads/")); m != nil {
		return m[1]
	}
	return ""
}
