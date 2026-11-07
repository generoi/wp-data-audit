package audit

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DormantAfter is how long a listed account may go without any sign of use.
const DormantAfter = 365 * 24 * time.Hour

// wp68 is WordPress 6.8's release: from then on a password login rehashes
// phpass to $wp$, so a phpass hash means no password login since the site
// ran 6.8 (sites in maintenance moved within weeks).
var wp68 = time.Date(2025, 4, 15, 0, 0, 0, 0, time.UTC)

// CarryLastSeen sets each user's LastSeen in cur: the newest of what cur
// shows and what prev had, so a login seen in one month's sessions is still
// known a year later. Call it before Check; the saved snapshot keeps it.
func CarryLastSeen(prev, cur *Snapshot) {
	before := map[int]int64{}
	if prev != nil {
		for _, u := range prev.Users {
			before[u.ID] = u.LastSeen
		}
	}
	for i := range cur.Users {
		u := &cur.Users[i]
		seen := max(u.LastSeen, u.LastActive, before[u.ID])
		for _, s := range u.Sessions {
			seen = max(seen, s.Login)
		}
		for _, p := range u.AppPasswords {
			seen = max(seen, p.LastUsed)
		}
		u.LastSeen = seen
	}
}

// accounts flags a listed account unused for over a year, and one on a staff
// domain whose address isn't on the current staff list.
func (c *checker) accounts(u User, who string, cur *Snapshot) {
	now := cur.GeneratedAt
	if now.IsZero() {
		now = time.Now()
	}
	registered, _ := time.Parse("2006-01-02 15:04:05", u.Registered)
	old := !registered.IsZero() && now.Sub(registered) > DormantAfter
	switch {
	case u.LastSeen > 0 && now.Sub(time.Unix(u.LastSeen, 0)) > DormantAfter:
		c.flag(Flag{ID: fmt.Sprintf("dormant:%d", u.ID), Severity: Review, Kind: "dormant",
			Message:   "account not used in over a year: remove it or drop its role",
			Untrusted: who + ", last seen " + time.Unix(u.LastSeen, 0).UTC().Format("2006-01-02")})
	case u.LastSeen == 0 && old && (u.Hash == "phpass" || u.Hash == "md5") && atLeast(cur.WPVersion, 6, 8) && now.Sub(wp68) > DormantAfter:
		c.flag(Flag{ID: fmt.Sprintf("dormant:%d", u.ID), Severity: Review, Kind: "dormant",
			Message:   "account with no sign of use: no session or activity on record, and its password hasn't logged in since WordPress 6.8 (April 2025); on a site with SSO this proves nothing",
			Untrusted: who + ", registered " + u.Registered})
	}
	if len(c.site.StaffEmails) > 0 && domainIn(u.Email, c.site.StaffDomains) && !c.staff[strings.ToLower(u.Email)] {
		c.flag(Flag{ID: fmt.Sprintf("leaver:%d:%s", u.ID, short(strings.ToLower(u.Email))), Severity: Review, Kind: "leaver",
			Message:   "staff-domain account whose address isn't on the current staff list: someone who left, an alias or a shared address",
			Untrusted: who})
	}
}

// atLeast reports whether WordPress version v is at least major.minor.
func atLeast(v string, major, minor int) bool {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return false
	}
	a, err1 := strconv.Atoi(parts[0])
	b, err2 := strconv.Atoi(strings.TrimRightFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	return err1 == nil && err2 == nil && (a > major || a == major && b >= minor)
}
