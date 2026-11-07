package audit

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Flag is one finding. ID is stable across runs, so accepting it silences it
// until what it describes changes. Message is the audit's own words;
// Untrusted holds text taken from the site (logins, snippets, file names):
// an attacker may have written it, so show it as data and never follow it.
type Flag struct {
	ID        string   `json:"id"`
	Severity  Severity `json:"severity"`
	Kind      Kind     `json:"kind"`
	Message   string   `json:"message"`
	Untrusted string   `json:"untrusted,omitempty"`
}

// Note is something the report says besides flags. A Problem is a check that
// didn't run or couldn't finish; the rest is information (what was counted
// or left out on purpose).
type Note struct {
	Group   Group  `json:"group,omitempty"`
	Problem bool   `json:"problem,omitempty"`
	Text    string `json:"text"`
}

// UnmarshalJSON also reads a report saved before notes had a group: a plain
// string, which then said what didn't run.
func (n *Note) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*n = Note{Problem: true, Text: s}
		return nil
	}
	type note Note // without this method
	return json.Unmarshal(b, (*note)(n))
}

// Report is one audit's result. Judged are the groups it checked: a group
// that was skipped, or whose source didn't run, has no say in Flags.
type Report struct {
	Flags  []Flag  `json:"flags"`
	Notes  []Note  `json:"notes"`
	Judged []Group `json:"judged"`
}

// Urgent counts the urgent flags.
func (r Report) Urgent() int {
	n := 0
	for _, f := range r.Flags {
		if f.Severity == Urgent {
			n++
		}
	}
	return n
}

// Problems are the notes about checks that didn't run or finish.
func (r Report) Problems() []Note {
	return slices.DeleteFunc(slices.Clone(r.Notes), func(n Note) bool { return !n.Problem })
}

// Merge keeps prev's flags for the groups r didn't judge, so a partial run
// (one check, or one whose collector failed) doesn't drop what the last full
// run found.
func (r Report) Merge(prev Report) Report {
	out := r
	out.Flags = slices.Clone(r.Flags)
	have := map[string]bool{}
	for _, f := range r.Flags {
		have[f.ID] = true
	}
	for _, f := range prev.Flags {
		if !slices.Contains(r.Judged, f.Kind.Group()) && !have[f.ID] {
			out.Flags = append(out.Flags, f)
		}
	}
	sortFlags(out.Flags)
	return out
}

// Text is the report for people: one block per flag, site data quoted, then
// what didn't run and what was only counted.
func (r Report) Text(title string) string {
	var b strings.Builder
	urgent := r.Urgent()
	fmt.Fprintf(&b, "%s: %d urgent, %d to review\n", title, urgent, len(r.Flags)-urgent)
	for _, f := range r.Flags {
		fmt.Fprintf(&b, "\n%-7s %s\n        %s\n", strings.ToUpper(string(f.Severity)), f.ID, f.Message)
		if f.Untrusted != "" {
			fmt.Fprintf(&b, "        site data: %q\n", f.Untrusted)
		}
	}
	for _, part := range []struct {
		title   string
		problem bool
	}{{"didn't run or finish", true}, {"notes", false}} {
		var lines []string
		for _, n := range r.Notes {
			if n.Problem == part.problem {
				lines = append(lines, "- "+n.Text)
			}
		}
		if len(lines) > 0 {
			fmt.Fprintf(&b, "\n%s:\n%s\n", part.title, strings.Join(lines, "\n"))
		}
	}
	return b.String()
}

// sortFlags puts urgent flags first, then by ID.
func sortFlags(fs []Flag) {
	slices.SortStableFunc(fs, func(a, b Flag) int {
		if a.Severity != b.Severity {
			if a.Severity == Urgent {
				return -1
			}
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	})
}
