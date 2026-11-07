package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Public is what each site's public URL gives away, asked from outside: one
// entry per home URL (a multisite's every site).
type Public struct {
	Sites []PublicSite `json:"sites"`
}

// PublicSite is one home URL's answers. Users are the REST API's user slugs
// (empty when it doesn't list them); AuthorSlug is where ?author=1 redirects.
type PublicSite struct {
	Home       string    `json:"home"`
	Err        string    `json:"err,omitempty"` // the home page didn't answer
	Users      []string  `json:"users,omitempty"`
	AuthorSlug string    `json:"author_slug,omitempty"`
	XMLRPC     bool      `json:"xmlrpc"`
	Listing    bool      `json:"uploads_listing"`
	Headers    []string  `json:"missing_headers,omitempty"`
	CertExpiry time.Time `json:"cert_expiry,omitzero"`
}

// reservedRE are names that are never a real site (RFC 2606, 6761):
// documentation and test domains are never asked.
var reservedRE = regexp.MustCompile(`(?i)(^|\.)(example\.(com|net|org)|example|test|invalid|localhost)$`)

func reserved(u string) bool {
	p, err := url.Parse(u)
	return err != nil || reservedRE.MatchString(p.Hostname())
}

// SiteURLs are the home and siteurl of every site from the collector's
// options ("home", "2:home", "2:siteurl"): home → siteurl.
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

// ProbePublic asks each home: the REST API's user list, ?author=1, XML-RPC
// (siteurl's xmlrpc.php, system.listMethods), the uploads folder's listing,
// the home page's security headers and TLS certificate. Read-only requests,
// at most six per site; uploads is the Bedrock path when bedrock is set.
func ProbePublic(ctx context.Context, client *http.Client, sites map[string]string, bedrock bool) *Public {
	if client == nil {
		client = NewClient()
	}
	p := &Public{}
	homes := slices.Sorted(func(yield func(string) bool) {
		for h := range sites {
			if !yield(h) {
				return
			}
		}
	})
	if len(homes) > 10 {
		homes = homes[:10]
	}
	p.Sites = make([]PublicSite, len(homes))
	var wg sync.WaitGroup
	for i, h := range homes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Sites[i] = probeSite(ctx, client, h, sites[h], bedrock)
		}()
	}
	wg.Wait()
	return p
}

func probeSite(ctx context.Context, client *http.Client, home, siteurl string, bedrock bool) PublicSite {
	s := PublicSite{Home: home}
	resp, err := get(ctx, client, home+"/", nil)
	if err == nil && resp.StatusCode/100 == 3 { // http → https, or to www: the headers are the landing page's
		resp.Body.Close()
		if loc, lerr := resp.Request.URL.Parse(resp.Header.Get("Location")); lerr == nil && !reserved(loc.String()) {
			resp, err = get(ctx, client, loc.String(), nil)
		}
	}
	if err != nil {
		s.Err = errText(err)
		return s
	}
	resp.Body.Close()
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

	if resp, err := get(ctx, client, home+"/wp-json/wp/v2/users", nil); err == nil {
		var users []struct {
			Slug string `json:"slug"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && json.Unmarshal(b, &users) == nil {
			for _, u := range users {
				if u.Slug != "" && len(s.Users) < 20 {
					s.Users = append(s.Users, firstN(u.Slug, 60))
				}
			}
		}
	}
	if resp, err := get(ctx, client, home+"/?author=1", nil); err == nil {
		resp.Body.Close()
		if loc := resp.Header.Get("Location"); resp.StatusCode/100 == 3 {
			if m := regexp.MustCompile(`/author/([^/?#]+)`).FindStringSubmatch(loc); m != nil {
				s.AuthorSlug = firstN(m[1], 60)
			}
		}
	}
	if siteurl == "" {
		siteurl = home
	}
	body := `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>`
	if resp, err := get(ctx, client, siteurl+"/xmlrpc.php", strings.NewReader(body)); err == nil {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		s.XMLRPC = resp.StatusCode == http.StatusOK && strings.Contains(string(b), "wp.getUsersBlogs")
	}
	uploads := home + "/wp-content/uploads/"
	if bedrock {
		uploads = home + "/app/uploads/"
	}
	s.Listing, _ = listed(ctx, client, uploads)
	return s
}

// get GETs u, or POSTs body (XML-RPC's text/xml) when there is one.
func get(ctx context.Context, client *http.Client, u string, body io.Reader) (*http.Response, error) {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wp-data-audit")
	if body != nil {
		req.Header.Set("Content-Type", "text/xml")
	}
	return client.Do(req)
}

// public flags what the public URLs give away.
func (c *checker) public(cur *Snapshot) {
	if cur.Public == nil {
		return
	}
	now := cur.GeneratedAt
	if now.IsZero() {
		now = time.Now()
	}
	for _, s := range cur.Public.Sites {
		host := strings.TrimPrefix(strings.TrimPrefix(s.Home, "https://"), "http://")
		switch {
		case s.Err != "":
			c.note(fmt.Sprintf("%s didn't answer: %s", s.Home, s.Err))
			continue
		case !s.CertExpiry.IsZero() && s.CertExpiry.Sub(now) < 14*24*time.Hour:
			c.flag(Flag{ID: "cert:" + idPart(host) + ":" + s.CertExpiry.UTC().Format("20060102"), Severity: Urgent, Kind: "public",
				Message: "the TLS certificate expires within two weeks", Untrusted: host + " until " + s.CertExpiry.UTC().Format("2006-01-02")})
		}
		if len(s.Users) > 0 {
			c.flag(Flag{ID: "rest-users:" + idPart(host), Severity: Review, Kind: "public",
				Message: "the REST API lists users to anyone, login slugs included (the REST wall isn't holding)", Untrusted: host + ": " + strings.Join(s.Users, ", ")})
		}
		if s.AuthorSlug != "" {
			c.flag(Flag{ID: "author-enum:" + idPart(host), Severity: Review, Kind: "public",
				Message: "?author=1 redirects to the author's slug, which gives away a login name", Untrusted: host + ": " + s.AuthorSlug})
		}
		if s.XMLRPC {
			c.flag(Flag{ID: "xmlrpc:" + idPart(host), Severity: Review, Kind: "public",
				Message: "XML-RPC answers: system.multicall lets one request try many passwords; disable it unless an app needs it", Untrusted: host})
		}
		if s.Listing {
			c.flag(Flag{ID: "listing:uploads:" + idPart(host), Severity: Urgent, Kind: "public",
				Message: "the web server lists the uploads folder's files", Untrusted: host})
		}
		if len(s.Headers) > 0 {
			c.flag(Flag{ID: "headers:" + idPart(host) + ":" + short(s.Headers...), Severity: Review, Kind: "public",
				Message: "security headers missing on the home page", Untrusted: host + ": " + strings.Join(s.Headers, ", ")})
		}
	}
}
