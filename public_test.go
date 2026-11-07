package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbePublic(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" && r.URL.Query().Get("author") == "1":
			http.Redirect(w, r, "/author/jane-admin/", http.StatusMovedPermanently)
		case r.URL.Path == "/":
			w.Header().Set("X-Content-Type-Options", "nosniff") // no HSTS, no framing rule
		case r.URL.Path == "/wp-json/wp/v2/users":
			w.Write([]byte(`[{"id":1,"slug":"jane-admin"},{"id":2,"slug":"editor"}]`))
		case r.URL.Path == "/wp/xmlrpc.php" && r.Method == http.MethodPost:
			w.Write([]byte(`<methodResponse><value><string>wp.getUsersBlogs</string></value></methodResponse>`))
		case r.URL.Path == "/app/uploads/":
			w.Write([]byte(`<html><head><title>Index of /app/uploads</title>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	sites := SiteURLs(map[string]string{"home": srv.URL, "siteurl": srv.URL + "/wp", "2:home": "https://two.example"})
	if len(sites) != 1 || sites[srv.URL] != srv.URL+"/wp" {
		t.Fatalf("sites %v (a reserved domain must be left out)", sites)
	}
	p := ProbePublic(context.Background(), client, sites, true)
	s := p.Sites[0]
	if s.Err != "" || strings.Join(s.Users, ",") != "jane-admin,editor" || s.AuthorSlug != "jane-admin" || !s.XMLRPC || !s.Listing || len(s.Headers) != 2 || s.CertExpiry.IsZero() {
		t.Fatalf("probe %+v", s)
	}

	cur := base0()
	cur.GeneratedAt = s.CertExpiry.Add(-5 * 24 * time.Hour)
	cur.Public = p
	kinds := map[string]string{}
	for _, f := range Check(nil, cur, Site{}, nil, nil).Flags {
		if f.Kind == "public" {
			kinds[strings.SplitN(f.ID, ":", 2)[0]] = f.Severity
		}
	}
	want := map[string]string{"cert": Urgent, "rest-users": Review, "author-enum": Review, "xmlrpc": Review, "listing": Urgent, "headers": Review}
	for k, sev := range want {
		if kinds[k] != sev {
			t.Errorf("%s: %q, want %s (all %v)", k, kinds[k], sev, kinds)
		}
	}
}
