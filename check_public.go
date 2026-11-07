package audit

import (
	"strings"
	"time"
)

// public: what each site's public URL gives away.
func (c *checker) public() {
	for _, s := range c.in.Facts.Web.Sites {
		host := strings.TrimPrefix(strings.TrimPrefix(s.Home, "https://"), "http://")
		if s.Err != "" {
			c.problem("%s didn't answer: %s", s.Home, s.Err)
			continue
		}
		if !s.CertExpiry.IsZero() && s.CertExpiry.Sub(c.now()) < 14*24*time.Hour {
			c.flag(Flag{ID: "cert:" + idPart(host) + ":" + s.CertExpiry.UTC().Format("20060102"), Severity: Urgent, Kind: KindPublic,
				Message: "the TLS certificate expires within two weeks", Untrusted: host + " until " + s.CertExpiry.UTC().Format("2006-01-02")})
		}
		if len(s.Users) > 0 {
			c.flag(Flag{ID: "rest-users:" + idPart(host), Severity: Review, Kind: KindPublic,
				Message: "the REST API lists users to anyone, login slugs included (the REST wall isn't holding)", Untrusted: host + ": " + strings.Join(s.Users, ", ")})
		}
		if s.AuthorSlug != "" {
			c.flag(Flag{ID: "author-enum:" + idPart(host), Severity: Review, Kind: KindPublic,
				Message: "?author=1 redirects to the author's slug, which gives away a login name", Untrusted: host + ": " + s.AuthorSlug})
		}
		if s.XMLRPC {
			c.flag(Flag{ID: "xmlrpc:" + idPart(host), Severity: Review, Kind: KindPublic,
				Message: "XML-RPC answers: system.multicall lets one request try many passwords; disable it unless an app needs it", Untrusted: host})
		}
		if s.Listing {
			c.flag(Flag{ID: "listing:uploads:" + idPart(host), Severity: Urgent, Kind: KindPublic,
				Message: "the web server lists the uploads folder's files", Untrusted: host})
		}
		if len(s.Headers) > 0 {
			c.flag(Flag{ID: "headers:" + idPart(host) + ":" + short(s.Headers...), Severity: Review, Kind: KindPublic,
				Message: "security headers missing on the home page", Untrusted: host + ": " + strings.Join(s.Headers, ", ")})
		}
	}
}
