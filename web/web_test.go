package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestProbeFiles(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/app/uploads/files/a.csv":
			w.Header().Set("Content-Type", "text/csv")
		case "/backup.sql":
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed) // falls back to a one-byte GET
				return
			}
			w.Header().Set("Content-Type", "application/sql")
		case "/app/uploads/files/":
			w.Write([]byte("<html><title>Index of /app/uploads/files</title>"))
		case "/app/uploads/old.zip":
			http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently) // not followed
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	w := Probe(context.Background(), nil, Target{Home: srv.URL + "/", Content: "web/app"},
		Options{Files: []string{"web/app/uploads/files/a.csv", "web/backup.sql", "web/app/uploads/old.zip"}})
	if w.Base != srv.URL {
		t.Fatalf("base %q", w.Base)
	}
	for p, want := range map[string]int{"web/app/uploads/files/a.csv": 200, "web/backup.sql": 200, "web/app/uploads/old.zip": 301} {
		if a := w.Files[p]; a.Status != want {
			t.Errorf("%s: %+v, want %d", p, a, want)
		}
	}
	if !w.Files["web/backup.sql"].Served() || !w.Listings["web/app/uploads/files"].Listed || w.Listings["web/app/uploads"].Listed {
		t.Fatalf("answers %+v, listings %+v", w.Files, w.Listings)
	}
	if strings.Contains(strings.Join(asked, "\n"), "elsewhere") {
		t.Fatal("followed a redirect")
	}
}

// A network whose main URL is dead: a file is asked for on a site's domain,
// which serves the same docroot; a site's uploads always on its own.
func TestProbeNetwork(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/csv")
	}))
	defer live.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	w := Probe(context.Background(), nil, Target{Home: dead.URL, Content: "web/app", Options: map[string]string{"2:home": live.URL + "/sv"}},
		Options{Files: []string{"web/app/uploads/wpallexport/exports/users.csv", "web/app/uploads/sites/2/x.csv"}})
	for _, p := range []string{"web/app/uploads/wpallexport/exports/users.csv", "web/app/uploads/sites/2/x.csv"} {
		if a := w.Files[p]; a.Status != 200 || a.Err != "" {
			t.Errorf("%s: %+v", p, a)
		}
	}
	if !strings.Contains(strings.Join(asked, "\n"), "/app/uploads/sites/2/x.csv") {
		t.Fatalf("asked %v", asked)
	}
}

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
	opts := map[string]string{"home": srv.URL, "siteurl": srv.URL + "/wp", "2:home": "https://two.example"}
	w := Probe(context.Background(), client, Target{Home: srv.URL, Options: opts}, Options{Public: true})
	if len(w.Sites) != 1 {
		t.Fatalf("sites %+v (a test domain must be left out)", w.Sites)
	}
	s := w.Sites[0]
	if s.Err != "" || strings.Join(s.Users, ",") != "jane-admin,editor" || s.AuthorSlug != "jane-admin" || !s.XMLRPC || !s.Listing || len(s.Headers) != 2 || s.CertExpiry.IsZero() {
		t.Fatalf("probe %+v", s)
	}
}

// A test domain is never asked: no request at all.
func TestProbeTestDomain(t *testing.T) {
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("a request to a test domain")
		return nil, nil
	})}
	w := Probe(context.Background(), client, Target{Home: "https://www.example.com", Options: map[string]string{"home": "https://www.example.com"}},
		Options{Files: []string{"web/backup.sql"}, Public: true})
	if w.Base != "" || len(w.Sites) != 0 {
		t.Fatalf("%+v", w)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBlogURLs(t *testing.T) {
	got := BlogURLs("https://main.example", map[string]string{"home": "https://main.example", "2:home": "https://two.example/sv", "2:siteurl": "https://x.example"})
	if len(got) != 1 || got["2"] != "https://two.example" {
		t.Fatalf("%v", got)
	}
}
