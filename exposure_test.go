package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestExposure(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/app/uploads/wpallimport/files/asiakkaat_2019.csv", "/app/uploads/2024/05/customers-export.xlsx":
			w.Header().Set("Content-Type", "text/csv")
		case "/backup.sql":
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed) // falls back to a one-byte GET
				return
			}
			w.Header().Set("Content-Type", "application/sql")
		case "/app/uploads/wpallimport/files/":
			w.Write([]byte("<html><title>Index of /app/uploads/wpallimport/files</title>"))
		case "/app/uploads/old.zip":
			http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently) // not followed: not the file
		case "/app/uploads/wc-logs/x.log":
			w.WriteHeader(http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rel := &Release{Content: "web/app", Data: []DataFile{
		{Path: "web/app/uploads/wpallimport/files/asiakkaat_2019.csv", Size: 10, Mtime: 1551900000},
		{Path: "web/app/uploads/2024/05/brochure.pdf", Size: 1, Mtime: 1},          // media library
		{Path: "web/app/uploads/2024/05/customers-export.xlsx", Size: 2, Mtime: 2}, // ...but its name
		{Path: "web/app/uploads/gravity_forms/1-abc/cv.pdf", Size: 3, Mtime: 1600000000},
		{Path: "web/app/uploads/wc-logs/x.log", Size: 4, Mtime: 4},
		{Path: "web/backup.sql", Size: 5, Mtime: 5},
		{Path: "web/wp-config.php", Size: 6, Mtime: 6},
		{Path: "web/app/plugins/woocommerce/sample-data/x.csv", Size: 7, Mtime: 7}, // no install to compare
		{Path: "web/app/uploads/old.zip", Size: 8, Mtime: 8},
	}}
	rel.Exposed = Candidates(rel, nil)
	if len(rel.Exposed.Files) != 5 {
		t.Fatalf("candidates %+v", rel.Exposed.Files)
	}
	rel.Exposed.Probe(context.Background(), nil, rel, DocrootURL(srv.URL+"/"), nil)
	if strings.Contains(strings.Join(asked, "\n"), "brochure") {
		t.Fatalf("asked about a media library file: %v", asked)
	}

	cur := base0()
	cur.Release = rel
	r := Check(nil, cur, Site{}, nil, nil)
	got := map[string]Flag{}
	for _, f := range r.Flags {
		if f.Kind == "exposed" {
			got[f.Untrusted[:strings.Index(f.Untrusted+" ", " ")]] = f
		}
	}
	for p, want := range map[string]string{
		"web/backup.sql": Urgent,
		"web/app/uploads/wpallimport/files:":                 Urgent, // grouped per plugin folder
		"web/app/uploads/2024/05/customers-export.xlsx":      Review, // media library: public on purpose
		"web/app/uploads/old.zip":                            Review,
		"web/app/uploads/wpallimport/files":                  Urgent, // listed
	} {
		if got[p].Severity != want {
			t.Errorf("%s: %+v, want %s", p, got[p], want)
		}
	}
	if len(got) != 5 {
		t.Errorf("flags %+v", got)
	}
	notes := strings.Join(r.Notes, "\n")
	for _, want := range []string{"1 documents in the media library", "1 Gravity Forms uploads", "oldest from 2020-09-13", "1 logs on the server", "1 data files in plugins"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}

	// Accepting holds until the file changes.
	var id string
	for _, f := range r.Flags {
		if strings.HasPrefix(f.Untrusted, "web/backup.sql") {
			id = f.ID
		}
	}
	r = Check(nil, cur, Site{Accepted: map[string]bool{id: true}}, nil, nil)
	for _, f := range r.Flags {
		if f.ID == id {
			t.Fatal("accepted flag came back")
		}
	}
	rel.Exposed.Files[0].Size++ // backup.sql ranks first
	r = Check(nil, cur, Site{Accepted: map[string]bool{id: true}}, nil, nil)
	if !strings.Contains(r.Flags[0].Untrusted+r.Flags[1].Untrusted+r.Flags[2].Untrusted+r.Flags[3].Untrusted, "backup.sql") {
		t.Fatalf("a changed file stayed accepted: %+v", r.Flags)
	}
}

func TestNoCandidatesNoRequests(t *testing.T) {
	rel := &Release{Content: "web/app", Data: []DataFile{{Path: "web/app/uploads/2024/05/menu.pdf"}}}
	rel.Exposed = Candidates(rel, nil)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("a request without candidates")
		return nil, nil
	})}
	rel.Exposed.Probe(context.Background(), client, rel, "https://site.example", nil)
}

// A network whose main URL is dead: its files are asked for on a site's
// domain. Complianz's folder and plugin JSON are only counted.
func TestExposureNetwork(t *testing.T) {
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
	}))
	defer live.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	rel := &Release{Content: "web/app", Data: []DataFile{
		{Path: "web/app/uploads/wpallexport/exports/a/users-export.csv"},
		{Path: "web/app/uploads/sites/2/complianz/snapshots/policy.pdf"},
		{Path: "web/app/uploads/sites/2/complianz/cmp/vendorlist/vendor-list.json"},
		{Path: "web/app/uploads/elementor/data.json"},
	}}
	rel.Exposed = Candidates(rel, nil)
	if len(rel.Exposed.Files) != 1 {
		t.Fatalf("candidates %+v", rel.Exposed.Files)
	}
	rel.Exposed.Probe(context.Background(), nil, rel, dead.URL, map[string]string{"2": live.URL})
	if f := rel.Exposed.Files[0]; f.Status != http.StatusOK || f.Err != "" {
		t.Fatalf("not retried on the site's domain: %+v", f)
	}
	notes := strings.Join(rel.Exposed.Notes, "\n")
	if !strings.Contains(notes, "2 files in folders a plugin serves") || !strings.Contains(notes, "1 JSON files") {
		t.Fatalf("notes %s", notes)
	}
}

func TestPersonalNames(t *testing.T) {
	for name, want := range map[string]bool{
		"asiakkaat_02_2019.csv": true, "members-2024.xlsx": true, "quotes-export-2025.zip": true,
		"jäsenrekisteri.xls": true, "orders.csv": true, "cv_jane.pdf": true, "users.json": true,
		"X100-User-Manual.pdf": false, "kaspar-hauser-story.pdf": false, "order-form.pdf": false,
		"application-note.pdf": false, "client-manager-job-description.pdf": false,
	} {
		if personal(name) != want {
			t.Errorf("personal(%q) = %v", name, !want)
		}
	}
}

func TestBlogURLs(t *testing.T) {
	rel := &Release{Content: "web/app"}
	e := &Exposure{Base: "https://main.example", Blogs: BlogURLs("https://main.example", map[string]string{
		"home": "https://main.example", "2:home": "https://two.example/sv", "2:siteurl": "https://x.example",
	})}
	if got := e.url(rel, "web/app/uploads/sites/2/x.csv"); got != "https://two.example/app/uploads/sites/2/x.csv" {
		t.Errorf("blog 2: %s", got)
	}
	if got := e.url(rel, "web/app/uploads/sites/3/x.csv"); got != "https://main.example/app/uploads/sites/3/x.csv" {
		t.Errorf("unknown blog: %s", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDataLine(t *testing.T) {
	d, err := dataLine("123 1551900000.1234567890 web/app/uploads//a b.csv")
	if err != nil || d.Path != "web/app/uploads/a b.csv" || d.Size != 123 || d.Mtime != 1551900000 {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := dataLine("x y"); err == nil {
		t.Fatal("bad line parsed")
	}
}
