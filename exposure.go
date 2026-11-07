package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Exposure is the hasher's DATA files worth asking the public URL about, and
// what it answered. Base is the docroot's public URL ("" when unknown: then
// nothing was asked).
type Exposure struct {
	Base string `json:"base"`
	// Blogs are a multisite's other sites' docroot URLs by blog id: their
	// uploads (uploads/sites/<id>/) are served on their own domain.
	Blogs    map[string]string `json:"blogs,omitempty"`
	Files    []Exposed `json:"files"`
	Listings []Listing `json:"listings,omitempty"`
	Notes    []string  `json:"notes,omitempty"`
}

// Exposed is one candidate. Status is the HTTP status of its public URL
// (0 with Err when the request failed), Type its Content-Type.
type Exposed struct {
	DataFile
	Kind   string `json:"kind"` // dump, backup, archive, log, secret, repo, document
	Why    string `json:"why"`
	Media  bool   `json:"media,omitempty"` // a media library upload: public on purpose, only its name is odd
	Status int    `json:"status"`
	Type   string `json:"type,omitempty"`
	Err    string `json:"err,omitempty"`
}

// Listing is a candidate's folder: whether its URL lists the folder.
type Listing struct {
	Dir    string `json:"dir"`
	Listed bool   `json:"listed"`
	Err    string `json:"err,omitempty"`
}

// MaxExposed caps the candidates asked about; the rest are a note.
const MaxExposed = 300

var (
	kindRE = []struct {
		kind string
		re   *regexp.Regexp
	}{
		{"repo", regexp.MustCompile(`(^|/)\.git/config$`)},
		{"dump", regexp.MustCompile(`(?i)\.(sql(\..+)?|dump|sqlite3?|db|mdb|wpress)$`)},
		{"secret", regexp.MustCompile(`(?i)((^|/)\.env(\..*)?|\.env|\.key|\.pem|\.p12|\.pfx)$`)},
		{"log", regexp.MustCompile(`(?i)\.log$`)},
		{"archive", regexp.MustCompile(`(?i)\.(zip|tar(\..+)?|tgz|7z|rar)$`)},
		{"backup", regexp.MustCompile(`(?i)(\.(bak|backup|old|orig|save|swp)|~|(^|/)wp-config[^/]*)$`)},
	}
	// Folders under uploads that a plugin serves to visitors on purpose:
	// Complianz's consent vendor lists, CSS and proof-of-consent policy PDFs.
	publicRE = regexp.MustCompile(`^(sites/\d+/)?complianz/`)
	mediaRE  = regexp.MustCompile(`^(sites/\d+/)?\d{4}/\d{2}/`)
	formsRE  = regexp.MustCompile(`^(sites/\d+/)?gravity_forms/`)
	blogRE   = regexp.MustCompile(`^sites/(\d+)/`)
	tokensRE = regexp.MustCompile(`\p{L}+`)

	// Words in a file name that suggest people's data, in English, Finnish
	// and Swedish: a word starting with one of personalStems, or one of
	// personalWords. Whole words only, so "User Guide", a surname like Hauser and
	// "order form" don't count, "users", "orders" and "asiakkaat" do.
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

func kindOf(p string) string {
	for _, k := range kindRE {
		if k.re.MatchString(p) {
			return k.kind
		}
	}
	return "document"
}

// Candidates picks from the hasher's DATA files what the public URL should
// be asked about: anything risky by type, and documents outside the media
// library (or in it under a name that suggests people's data). Files the
// checkout's install has at the same path are the release's own.
func Candidates(rel *Release, exp *Repo) *Exposure {
	e := &Exposure{}
	if rel == nil || len(rel.Data) == 0 {
		return e
	}
	content := rel.Content
	uploads := content + "/uploads/"
	compare := exp != nil && exp.Dir != "" && !stale(rel, exp)
	var media, forms, unchecked, public, jsons int
	var oldestForm int64
	for _, d := range rel.Data {
		p := d.Path
		name := path.Base(p)
		if name == "wp-config.php" || name == "wp-config-sample.php" {
			continue
		}
		inUploads := strings.HasPrefix(p, uploads)
		if !inUploads {
			if compare {
				if _, err := os.Stat(filepath.Join(exp.Dir, filepath.FromSlash(p))); err == nil {
					continue
				}
			} else if shipped(p, content) {
				unchecked++
				continue
			}
		}
		k := kindOf(p)
		why := ""
		rest := strings.TrimPrefix(p, uploads)
		isMedia := inUploads && (k == "document" || k == "archive") && mediaRE.MatchString(rest)
		switch {
		case !inUploads:
			why = map[bool]string{true: "outside the media library", false: k + " in the docroot"}[k == "document"]
		case formsRE.MatchString(rest) && (k == "document" || k == "archive"):
			forms++
			if oldestForm == 0 || d.Mtime < oldestForm {
				oldestForm = d.Mtime
			}
			continue
		case isMedia && !personal(name):
			media++
			continue
		case publicRE.MatchString(rest) && (k == "document" || k == "archive"):
			public++
			continue
		case k == "document" && strings.HasSuffix(strings.ToLower(name), ".json") && !personal(name):
			jsons++ // plugins' own data and caches; an export with a telling name still counts
			continue
		case isMedia:
			why = "a media library upload whose name suggests people's data"
		case personal(name):
			why = "the name suggests people's data"
		case k == "document" || k == "archive":
			why = "in a plugin's folder under uploads, not the media library"
		default:
			why = k + " under uploads"
		}
		e.Files = append(e.Files, Exposed{DataFile: d, Kind: k, Why: why, Media: isMedia})
	}
	rank := map[string]int{"dump": 0, "secret": 1, "repo": 2, "backup": 3, "archive": 4, "document": 5, "log": 6}
	slices.SortStableFunc(e.Files, func(a, b Exposed) int {
		if r := rank[a.Kind] - rank[b.Kind]; r != 0 {
			return r
		}
		return strings.Compare(a.Path, b.Path)
	})
	if n := len(e.Files); n > MaxExposed {
		e.Notes = append(e.Notes, fmt.Sprintf("%d more candidate files weren't checked (over %d)", n-MaxExposed, MaxExposed))
		e.Files = e.Files[:MaxExposed]
	}
	if media > 0 {
		e.Notes = append(e.Notes, fmt.Sprintf("%d documents in the media library not checked: uploaded on purpose, no name suggests people's data", media))
	}
	if public > 0 {
		e.Notes = append(e.Notes, fmt.Sprintf("%d files in folders a plugin serves on purpose (Complianz) not checked", public))
	}
	if jsons > 0 {
		e.Notes = append(e.Notes, fmt.Sprintf("%d JSON files under uploads not checked: plugins' own data, no name suggests people's data", jsons))
	}
	if forms > 0 {
		e.Notes = append(e.Notes, fmt.Sprintf("%d Gravity Forms uploads (public to anyone with the link), the oldest from %s: worth a retention policy", forms, time.Unix(oldestForm, 0).UTC().Format("2006-01-02")))
	}
	if unchecked > 0 {
		e.Notes = append(e.Notes, fmt.Sprintf("%d data files in plugins, themes and core not checked: no install of the deployed commit to tell the release's own from added ones", unchecked))
	}
	return e
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
	n := min(2, len(parts)-1)
	return uploads + prefix + strings.Join(parts[:n], "/")
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

// stale: the checkout is at another commit than production, so it says
// nothing about which files production's release ships.
func stale(rel *Release, exp *Repo) bool {
	return exp != nil && rel.Revision != "" && exp.Revision != "" &&
		!strings.HasPrefix(exp.Revision, rel.Revision) && !strings.HasPrefix(rel.Revision, exp.Revision)
}

// DocrootURL is the public URL of the release's docroot from the site's
// home URL: Bedrock serves web/ at the home URL, plain WordPress its root.
func DocrootURL(home string) string {
	u, err := url.Parse(home)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	u.Path, u.RawQuery, u.Fragment = strings.TrimSuffix(u.Path, "/"), "", ""
	return u.String()
}

// BlogURLs are the docroot URLs of a multisite's other sites from the
// collector's blog-tagged home options ("2:home"): each site's own host with
// the main docroot's path, as uploads aren't under a subdirectory site's path.
func BlogURLs(base string, options map[string]string) map[string]string {
	b, err := url.Parse(base)
	if base == "" || err != nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range options {
		id, ok := strings.CutSuffix(k, ":home")
		if !ok {
			continue
		}
		if u, err := url.Parse(v); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			out[id] = u.Scheme + "://" + u.Host + b.Path
		}
	}
	return out
}

func (e *Exposure) url(rel *Release, p string) string {
	base := e.Base
	if m := blogRE.FindStringSubmatch(strings.TrimPrefix(p, rel.Content+"/uploads/")); m != nil && e.Blogs[m[1]] != "" {
		base = e.Blogs[m[1]]
	}
	if rel.Content == "web/app" {
		p = strings.TrimPrefix(p, "web/")
	}
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return base + "/" + strings.Join(parts, "/")
}

// NewClient is the client Probe uses by default: no redirects (a redirect
// isn't the file), short timeouts.
func NewClient() *http.Client {
	return &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Probe asks base (DocrootURL), or a multisite's own site (BlogURLs) for its
// uploads, for every candidate with HEAD (a one-byte GET where HEAD isn't
// allowed) and fetches each candidate's folder to see whether it's listed.
// No file's content is read.
func (e *Exposure) Probe(ctx context.Context, client *http.Client, rel *Release, base string, blogs map[string]string) {
	e.Base, e.Blogs = base, blogs
	if base == "" || len(e.Files) == 0 {
		return
	}
	if client == nil {
		client = NewClient()
	}
	// A network's main URL may not be live (only its sites' domains are), but
	// every site's domain serves the same docroot: try one when it fails.
	alt := ""
	if ids := slices.Sorted(maps.Keys(blogs)); len(ids) > 0 {
		alt = blogs[ids[0]]
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i := range e.Files {
		wg.Add(1)
		sem <- struct{}{}
		go func(f *Exposed) {
			defer func() { <-sem; wg.Done() }()
			u := e.url(rel, f.Path)
			f.Status, f.Type, f.Err = head(ctx, client, u)
			if rest, ok := strings.CutPrefix(u, e.Base+"/"); ok && f.Err != "" && alt != "" && alt != e.Base {
				f.Status, f.Type, f.Err = head(ctx, client, alt+"/"+rest)
			}
		}(&e.Files[i])
	}
	dirs := map[string]bool{}
	for _, f := range e.Files {
		if len(dirs) < 20 {
			dirs[path.Dir(f.Path)] = true
		}
	}
	for _, d := range slices.Sorted(func(yield func(string) bool) {
		for d := range dirs {
			if !yield(d) {
				return
			}
		}
	}) {
		e.Listings = append(e.Listings, Listing{Dir: d})
	}
	for i := range e.Listings {
		wg.Add(1)
		sem <- struct{}{}
		go func(l *Listing) {
			defer func() { <-sem; wg.Done() }()
			l.Listed, l.Err = listed(ctx, client, e.url(rel, l.Dir)+"/")
		}(&e.Listings[i])
	}
	wg.Wait()
}

func request(ctx context.Context, client *http.Client, method, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wp-data-audit")
	if method == http.MethodGet {
		req.Header.Set("Range", "bytes=0-0")
	}
	return client.Do(req)
}

func head(ctx context.Context, client *http.Client, u string) (int, string, string) {
	resp, err := request(ctx, client, http.MethodHead, u)
	if err == nil && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented) {
		resp.Body.Close()
		resp, err = request(ctx, client, http.MethodGet, u)
	}
	if err != nil {
		return 0, "", errText(err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Content-Type"), ""
}

var indexRE = regexp.MustCompile(`(?i)<title>\s*index of|<h1>\s*index of`)

// listed GETs a folder URL and looks for a server's directory listing in
// the first 8 KB; nothing of it is kept.
func listed(ctx context.Context, client *http.Client, u string) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, errText(err)
	}
	req.Header.Set("User-Agent", "wp-data-audit")
	resp, err := client.Do(req)
	if err != nil {
		return false, errText(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	return indexRE.Match(b), ""
}

// exposed turns the probe's answers into flags: a file the public URL hands
// out is urgent, so is a listed folder; a risky file the server only keeps
// is for review; blocked logs and documents are only counted.
func (c *checker) exposed(cur *Snapshot) {
	if cur.Release == nil || cur.Release.Exposed == nil {
		return
	}
	e := cur.Release.Exposed
	for _, n := range e.Notes {
		c.note(n)
	}
	if len(e.Files) == 0 {
		return
	}
	if e.Base == "" {
		c.note(fmt.Sprintf("%d files that may be public weren't checked: no site URL to ask", len(e.Files)))
		return
	}
	blocked := map[string]int{}
	groups := map[string][]Exposed{} // served files in a plugin's folder under uploads
	uploads := cur.Release.Content + "/uploads/"
	for _, f := range e.Files {
		at := fmt.Sprintf("%s (%d bytes, %s)", f.Path, f.Size, time.Unix(f.Mtime, 0).UTC().Format("2006-01-02"))
		id := "exposed:" + idPart(f.Path) + ":" + short(fmt.Sprint(f.Size), fmt.Sprint(f.Mtime))
		served := f.Status == http.StatusOK || f.Status == http.StatusPartialContent
		if g := pluginFolder(f.Path, uploads); served && !f.Media && g != "" && !strings.HasPrefix(f.Type, "text/html") {
			groups[g] = append(groups[g], f)
			continue
		}
		switch {
		case served && f.Media:
			c.flag(Flag{ID: id, Severity: Review, Kind: "exposed",
				Message: f.Kind + " anyone can download (" + f.Why + "): check it's meant to be public", Untrusted: at})
		case served && !strings.HasPrefix(f.Type, "text/html"):
			c.flag(Flag{ID: id, Severity: Urgent, Kind: "exposed",
				Message: f.Kind + " anyone can download (" + f.Why + ")", Untrusted: at})
		case served:
			c.flag(Flag{ID: id, Severity: Review, Kind: "exposed",
				Message: f.Kind + ": its URL answers 200 with a web page, open it to check (" + f.Why + ")", Untrusted: at})
		case f.Err != "":
			c.flag(Flag{ID: id, Severity: Review, Kind: "exposed",
				Message: f.Kind + ": its public URL couldn't be checked: " + f.Err, Untrusted: at})
		case f.Kind == "log" || f.Kind == "document":
			blocked[f.Kind]++
		default:
			c.flag(Flag{ID: id, Severity: Review, Kind: "exposed",
				Message: fmt.Sprintf("%s on the server, not served (HTTP %d): delete it if nothing needs it", f.Kind, f.Status), Untrusted: at})
		}
	}
	// One flag per plugin folder, its ID covering every file in it, so
	// accepting holds until any of them changes or a new one appears.
	for _, g := range slices.Sorted(maps.Keys(groups)) {
		fs := groups[g]
		var sig, list []string
		kinds := map[string]int{}
		for _, f := range fs {
			sig = append(sig, f.Path, fmt.Sprint(f.Size), fmt.Sprint(f.Mtime))
			kinds[f.Kind]++
			if len(list) < 20 {
				list = append(list, strings.TrimPrefix(f.Path, g+"/"))
			}
		}
		if len(fs) > len(list) {
			list = append(list, fmt.Sprintf("… %d more", len(fs)-len(list)))
		}
		var what []string
		for _, k := range slices.Sorted(maps.Keys(kinds)) {
			what = append(what, fmt.Sprintf("%d %s", kinds[k], k))
		}
		c.flag(Flag{ID: "exposed:" + idPart(g) + ":" + short(sig...), Severity: Urgent, Kind: "exposed",
			Message: fmt.Sprintf("%d files anyone can download in a plugin's folder under uploads (%s)", len(fs), strings.Join(what, ", ")),
			Untrusted: g + ": " + strings.Join(list, ", ")})
	}
	for _, k := range slices.Sorted(maps.Keys(blocked)) {
		c.note(fmt.Sprintf("%d %ss on the server that the public URL doesn't serve", blocked[k], k))
	}
	for _, l := range e.Listings {
		if l.Listed {
			c.flag(Flag{ID: "listing:" + idPart(l.Dir), Severity: Urgent, Kind: "exposed",
				Message: "the web server lists this folder's files", Untrusted: l.Dir})
		}
	}
}

func errText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err // the URL is already known
	}
	return firstN(err.Error(), 120)
}
