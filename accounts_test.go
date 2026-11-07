package audit

import (
	"strings"
	"testing"
	"time"
)

func TestDormantAndLeavers(t *testing.T) {
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	ago := func(d int) int64 { return now.AddDate(0, 0, -d).Unix() }
	admin := func(id int, email string) User {
		return User{ID: id, Email: email, Roles: []string{"administrator"}, Privileged: true,
			Registered: "2020-01-01 00:00:00", Hash: "wp-bcrypt"}
	}
	active := admin(1, "jane@staff.example")
	active.Sessions = []Session{{Login: ago(10)}}
	stale := admin(2, "Old@Staff.example") // left; seen once, 400 days ago
	unused := admin(3, "x@client.example")
	unused.Hash = "phpass" // no login since 6.8, nothing on record
	fresh := admin(4, "y@client.example")
	fresh.Hash, fresh.Registered = "phpass", "2026-10-01 00:00:00" // too new to judge
	api := admin(5, "bot@client.example")
	api.Hash, api.AppPasswords = "phpass", []AppPassword{{UUID: "u", LastUsed: ago(3)}}

	prev := &Snapshot{Users: []User{{ID: 2, LastSeen: ago(400)}}}
	cur := base0()
	cur.GeneratedAt, cur.WPVersion = now, "6.9.1"
	cur.Users = []User{active, stale, unused, fresh, api}
	CarryLastSeen(prev, cur)
	if cur.Users[1].LastSeen != ago(400) || cur.Users[4].LastSeen != ago(3) {
		t.Fatalf("last seen %+v", cur.Users)
	}
	r := Check(prev, cur, Site{StaffDomains: []string{"staff.example"}, StaffEmails: []string{"JANE@staff.example"}}, nil, nil)
	var got []string
	for _, f := range r.Flags {
		if f.Kind == "dormant" || f.Kind == "leaver" {
			got = append(got, strings.Join(strings.SplitN(f.ID, ":", 3)[:2], ":"))
		}
	}
	want := "dormant:2 dormant:3 leaver:2"
	if strings.Join(got, " ") != want {
		t.Fatalf("flags %v, want %s", got, want)
	}

	// Before 6.8 a phpass hash means nothing.
	cur.WPVersion = "6.7.2"
	for _, f := range Check(prev, cur, Site{}, nil, nil).Flags {
		if f.ID == "dormant:3" {
			t.Fatal("dormant from a hash on a site before 6.8")
		}
	}
}
