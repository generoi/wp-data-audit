// Package web asks a site's public URLs what they give away, from outside:
// whether files that shouldn't be public are served, folders listed, users
// listed, XML-RPC open, headers missing, the certificate about to expire. It
// only reads (HEAD, one-byte GETs, a listing's first 8 KB) and never asks a
// documentation or test domain (RFC 2606, 6761).
package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	audit "github.com/generoi/wp-data-audit"
)

// Target is where the site is: its home URL and the collector's options (a
// multisite's other sites: "2:home"), and its content folder (web/app on
// Bedrock, whose docroot is web/; "" means Bedrock).
type Target struct {
	Home    string
	Options map[string]string
	Content string
}

func (t Target) bedrock() bool { return t.Content == "" || t.Content == "web/app" }

// Options say what to ask: Files are candidate paths (audit.Candidates),
// Public the public-site checks.
type Options struct {
	Files  []string
	Public bool
}

// concurrency is how many requests a probe has in flight at once, so a site
// is asked politely; the client keeps as many connections open per host, so
// each request after the first reuses one instead of a new TLS handshake.
const concurrency = 6

// NewClient is the default client: no redirects (a redirect isn't the file),
// short timeouts, connections kept for reuse.
func NewClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = concurrency
	return &http.Client{
		Transport:     tr,
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Probe asks t's public URLs. Base is "" in the result when t has no usable
// home URL (or a test domain's): then nothing was asked.
func Probe(ctx context.Context, client *http.Client, t Target, o Options) *audit.WebFacts {
	w := &audit.WebFacts{Files: map[string]audit.Answer{}, Listings: map[string]audit.Listing{}}
	base := DocrootURL(t.Home)
	if base == "" || reserved(base) {
		return w
	}
	w.Base = base
	if client == nil {
		client = NewClient()
	}
	p := &prober{ctx: ctx, client: client, t: t, base: base, blogs: BlogURLs(base, t.Options), sem: make(chan struct{}, concurrency)}
	var wg sync.WaitGroup
	var mu sync.Mutex
	set := func(f func()) { mu.Lock(); f(); mu.Unlock() }
	// One goroutine per request at most concurrency at a time (do holds the
	// limit), started as slots free up rather than all at once.
	work := make(chan func())
	for range concurrency {
		wg.Go(func() {
			for f := range work {
				f()
			}
		})
	}
	dirs := map[string]bool{}
	for _, f := range o.Files {
		if len(dirs) < 20 {
			dirs[path.Dir(f)] = true
		}
	}
	go func() {
		defer close(work)
		for _, f := range o.Files {
			work <- func() {
				a := p.file(f)
				set(func() { w.Files[f] = a })
			}
		}
		for d := range dirs {
			work <- func() {
				listed, err := p.listed(p.url(d) + "/")
				set(func() { w.Listings[d] = audit.Listing{Listed: listed, Err: err} })
			}
		}
	}()
	if o.Public {
		sites := SiteURLs(t.Options)
		homes := slices.Sorted(maps.Keys(sites))
		if len(homes) > 10 {
			homes = homes[:10]
		}
		w.Sites = make([]audit.PublicSite, len(homes))
		for i, h := range homes {
			wg.Go(func() { w.Sites[i] = p.site(h, sites[h]) })
		}
	}
	wg.Wait()
	return w
}

type prober struct {
	ctx    context.Context
	client *http.Client
	t      Target
	base   string
	blogs  map[string]string
	sem    chan struct{} // at most concurrency requests at once, every kind
}

// url is path p's public URL: on its multisite site's own domain for its
// uploads, Bedrock's web/ being the docroot.
func (p *prober) url(rel string) string {
	base := p.base
	content := p.t.Content
	if content == "" {
		content = "web/app"
	}
	if b := p.blogs[audit.UploadsBlog(rel, content)]; b != "" {
		base = b
	}
	if p.t.bedrock() {
		rel = strings.TrimPrefix(rel, "web/")
	}
	parts := strings.Split(rel, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return base + "/" + strings.Join(parts, "/")
}

// file asks for one candidate with HEAD (a one-byte GET where HEAD isn't
// allowed). A network's main URL may not be live (only its sites' domains
// are), but every site's domain serves the same docroot: one is tried when
// the main one fails.
func (p *prober) file(rel string) audit.Answer {
	u := p.url(rel)
	a := p.head(u)
	if rest, ok := strings.CutPrefix(u, p.base+"/"); ok && a.Err != "" {
		if ids := slices.Sorted(maps.Keys(p.blogs)); len(ids) > 0 && p.blogs[ids[0]] != p.base {
			a = p.head(p.blogs[ids[0]] + "/" + rest)
		}
	}
	return a
}

func (p *prober) head(u string) audit.Answer {
	resp, err := p.do(http.MethodHead, u, nil, 0)
	if err == nil && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented) {
		done(resp)
		resp, err = p.do(http.MethodGet, u, nil, 1)
	}
	if err != nil {
		return audit.Answer{Err: errText(err)}
	}
	done(resp)
	return audit.Answer{Status: resp.StatusCode, Type: resp.Header.Get("Content-Type")}
}

var indexRE = regexp.MustCompile(`(?i)<title>\s*index of|<h1>\s*index of`)

// listed GETs a folder URL and looks for a directory listing in its first
// 8 KB; nothing of it is kept.
func (p *prober) listed(u string) (bool, string) {
	resp, err := p.do(http.MethodGet, u, nil, 8<<10)
	if err != nil {
		return false, errText(err)
	}
	defer done(resp)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return false, ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	return indexRE.Match(b), ""
}

var authorRE = regexp.MustCompile(`/author/([^/?#]+)`)

// site asks one home: the landing page's security headers and certificate,
// the REST API's user list, ?author=1, XML-RPC (siteurl's xmlrpc.php,
// system.listMethods) and the uploads folder's listing.
func (p *prober) site(home, siteurl string) audit.PublicSite {
	s := audit.PublicSite{Home: home}
	// The whole landing page, not a range: some servers add security headers
	// only to full answers. Only its headers are read.
	resp, err := p.do(http.MethodGet, home+"/", nil, 0)
	if err == nil && resp.StatusCode/100 == 3 { // http → https, or to www: the headers are the landing page's
		done(resp)
		if loc, lerr := resp.Request.URL.Parse(resp.Header.Get("Location")); lerr == nil && !reserved(loc.String()) {
			resp, err = p.do(http.MethodGet, loc.String(), nil, 0)
		}
	}
	if err != nil {
		s.Err = errText(err)
		return s
	}
	done(resp)
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		s.CertExpiry = resp.TLS.PeerCertificates[0].NotAfter
	}
	h := resp.Header
	if strings.HasPrefix(home, "https://") && h.Get("Strict-Transport-Security") == "" {
		s.Headers = append(s.Headers, "Strict-Transport-Security")
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors") {
		s.Headers = append(s.Headers, "X-Frame-Options or CSP frame-ancestors")
	}
	if !strings.EqualFold(h.Get("X-Content-Type-Options"), "nosniff") {
		s.Headers = append(s.Headers, "X-Content-Type-Options")
	}
	// The user list is decoded as it arrives, its first 20 slugs kept.
	if resp, err := p.do(http.MethodGet, home+"/wp-json/wp/v2/users", nil, 0); err == nil {
		if resp.StatusCode == http.StatusOK {
			dec := json.NewDecoder(io.LimitReader(resp.Body, 256<<10))
			if t, err := dec.Token(); err == nil && t == json.Delim('[') {
				for dec.More() && len(s.Users) < 20 {
					var u struct {
						Slug string `json:"slug"`
					}
					if dec.Decode(&u) != nil {
						break
					}
					if u.Slug != "" {
						s.Users = append(s.Users, firstN(u.Slug, 60))
					}
				}
			}
		}
		done(resp)
	}
	if resp, err := p.do(http.MethodGet, home+"/?author=1", nil, 1); err == nil {
		done(resp)
		if m := authorRE.FindStringSubmatch(resp.Header.Get("Location")); resp.StatusCode/100 == 3 && m != nil {
			s.AuthorSlug = firstN(m[1], 60)
		}
	}
	if siteurl == "" {
		siteurl = home
	}
	body := `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>`
	if resp, err := p.do(http.MethodPost, siteurl+"/xmlrpc.php", strings.NewReader(body), 0); err == nil {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		done(resp)
		s.XMLRPC = resp.StatusCode == http.StatusOK && bytes.Contains(b, []byte("wp.getUsersBlogs"))
	}
	uploads := home + "/wp-content/uploads/"
	if p.t.bedrock() {
		uploads = home + "/app/uploads/"
	}
	s.Listing, _ = p.listed(uploads)
	return s
}

// do sends one request within the probe's limit: a GET asks for its first n
// bytes only (Range) when n > 0, so a 2 GB dump isn't sent to be thrown away;
// a POST with a body is XML-RPC's text/xml.
func (p *prober) do(method, u string, body io.Reader, n int64) (*http.Response, error) {
	req, err := http.NewRequestWithContext(p.ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wp-data-audit")
	if body != nil {
		req.Header.Set("Content-Type", "text/xml")
	}
	if method == http.MethodGet && n > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", n-1))
	}
	select {
	case p.sem <- struct{}{}:
	case <-p.ctx.Done():
		return nil, context.Cause(p.ctx)
	}
	defer func() { <-p.sem }()
	return p.client.Do(req)
}

// done closes a response, first reading what's left of a short body so its
// connection goes back to the pool; a long one is cut (the connection with it).
func done(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
	resp.Body.Close()
}

// reservedRE are names that are never a real site (RFC 2606, 6761).
var reservedRE = regexp.MustCompile(`(?i)(^|\.)(example\.(com|net|org)|example|test|invalid|localhost)$`)

func reserved(u string) bool {
	p, err := url.Parse(u)
	return err != nil || reservedRE.MatchString(p.Hostname())
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

// BlogURLs are the docroot URLs of a multisite's other sites by blog id,
// from the blog-tagged home options ("2:home"): each site's own host with
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

// SiteURLs are every site's home → siteurl from the collector's options
// ("home", "2:home", "2:siteurl"), test domains left out.
func SiteURLs(options map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range options {
		prefix, ok := strings.CutSuffix(k, "home")
		if !ok || (prefix != "" && !strings.HasSuffix(prefix, ":")) {
			continue
		}
		if u := DocrootURL(v); u != "" && !reserved(u) {
			out[u] = DocrootURL(options[prefix+"siteurl"])
		}
	}
	return out
}

func errText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err // the URL is already known
	}
	return firstN(err.Error(), 120)
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
