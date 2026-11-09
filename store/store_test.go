package store

import (
	"strings"
	"testing"

	audit "github.com/generoi/wp-data-audit"
)

// Accepted flags read back with their scope, and list per scope.
func TestDecisionsText(t *testing.T) {
	s := Store{Root: t.TempDir()}
	k := Key{Site: "site", Env: "production"}
	err := s.SaveReport(k, audit.Report{Flags: []audit.Flag{
		{ID: "user:1:a", Kind: audit.KindUser, Message: "account", Untrusted: "user 1"},
		{ID: "content:b", Kind: audit.KindContent, Message: "iframe", Untrusted: "www.youtube.com"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(k, []string{"user:1:a"}, "staff", "me", false); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(k, []string{"content:b"}, "video", "me", true); err != nil {
		t.Fatal(err)
	}
	ds, err := s.Decisions(k)
	if err != nil || len(ds) != 2 || ds[0].Everywhere || !ds[1].Everywhere {
		t.Fatalf("decisions %+v %v", ds, err)
	}
	text := DecisionsText("site @production", ds)
	site, every, _ := strings.Cut(text, "every site")
	if !strings.Contains(site, "user:1:a") || !strings.Contains(every, "content:b") || !strings.Contains(every, "was: iframe: www.youtube.com") {
		t.Fatalf("text:\n%s", text)
	}
}
