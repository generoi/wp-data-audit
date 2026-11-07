package audit

import (
	"slices"
	"time"
)

type fakeGeo map[string]string

func (g fakeGeo) Country(ip string) string { return g[ip] }

var now = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

// site0 is a site with one admin and two sessions.
func site0() *SiteFacts {
	return &SiteFacts{
		Version: 1,
		Home:    "https://site.example",
		Options: map[string]string{"siteurl": "https://site.example/wp", "home": "https://site.example", "admin_email": "admin@staff.example"},
		Users: []User{{
			ID: 1, Login: "admin", Email: "admin@staff.example", Roles: []string{"administrator"}, Privileged: true,
			Sessions: []Session{{IP: "203.0.113.1", Login: now.Add(-time.Hour).Unix()}, {IP: "203.0.113.2", Login: now.Add(-time.Hour).Unix()}},
		}},
	}
}

// baselineOf is the baseline a full run of s leaves.
func baselineOf(s *SiteFacts) *Baseline { return newBaseline(now, s, lastSeen(nil, s)) }

// judge checks s (and files, web) against prev under p.
func judge(prev *Baseline, s *SiteFacts, p Policy, repo *Repo) Report {
	return Check(Input{Facts: Facts{At: now, Site: s}, Prev: prev, Repo: repo, Policy: p}).Report
}

// ids are r's flag IDs and severities.
func ids(r Report) map[string]Severity {
	m := map[string]Severity{}
	for _, f := range r.Flags {
		m[f.ID] = f.Severity
	}
	return m
}

// kind are r's flags of kind k.
func kind(r Report, k Kind) []Flag {
	return slices.DeleteFunc(slices.Clone(r.Flags), func(f Flag) bool { return f.Kind != k })
}

func noteTexts(r Report) string {
	var s string
	for _, n := range r.Notes {
		s += n.Text + "\n"
	}
	return s
}
