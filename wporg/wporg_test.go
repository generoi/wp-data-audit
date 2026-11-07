package wporg

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	audit "github.com/generoi/wp-data-audit"
)

// wordpress.org's three answers (as the live API gives them): a plugin, a
// closed one (404 with closed), and one it doesn't know (left out).
func TestLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") != "plugin_information" || r.URL.Query().Get("request[fields][sections]") != "0" {
			t.Errorf("query %s", r.URL.RawQuery)
		}
		switch r.URL.Query().Get("request[slug]") {
		case "live":
			w.Write([]byte(`{"slug":"live","last_updated":"2026-08-18 11:42pm GMT"}`))
		case "closed":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"closed","closed":true,"closed_date":"2025-10-06","reason":"security-issue","reason_text":"Security Issue"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"Plugin not found."}`))
		}
	}))
	defer srv.Close()
	got := Lookup(context.Background(), srv.Client(), srv.URL+"/", []string{"live", "closed", "premium"})
	if len(got) != 2 || got["live"] != (audit.WPOrgPlugin{LastUpdated: "2026-08-18"}) ||
		got["closed"] != (audit.WPOrgPlugin{Closed: true, Reason: "Security Issue", ClosedDate: "2025-10-06"}) {
		t.Fatalf("lookup %+v", got)
	}
}
