package audit

import (
	"strings"
	"testing"
	"time"
)

func TestRetention(t *testing.T) {
	cur := base0()
	cur.GeneratedAt = time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	cur.Retention = Retention{
		Forms: []FormRetention{
			{Blog: 1, FormID: 1, Title: "Contact", Entries: 900, Oldest: "2019-03-01 10:00:00", Policy: "retain"},
			{Blog: 1, FormID: 2, Title: "Jobs", Entries: 40, Oldest: "2020-01-01 10:00:00", Policy: "delete", Days: 180},
			{Blog: 1, FormID: 3, Title: "New", Entries: 5, Oldest: "2026-06-01 10:00:00", Policy: "retain"},
		},
		Woo: []WooRetention{
			{Blog: 1, Orders: 5000, Oldest: "2018-05-01 00:00:00", Settings: map[string]string{"anonymize_completed_orders": "", "delete_inactive_accounts": "24 months"}},
			{Blog: 2, Orders: 10, Oldest: "2018-05-01 00:00:00", Settings: map[string]string{"anonymize_completed_orders": "7 years"}},
		},
	}
	got := map[string]bool{}
	for _, f := range Check(nil, cur, Site{}, nil, nil).Flags {
		if f.Kind == "retention" {
			got[f.ID] = true
		}
	}
	forms := 0
	for id := range got {
		if strings.HasPrefix(id, "retention:forms:1:") {
			forms++
		}
	}
	if len(got) != 2 || forms != 1 || !got["retention:woo:1"] {
		t.Fatalf("flags %v", got)
	}
}
