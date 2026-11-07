package audit

import (
	"fmt"
	"maps"
	"slices"
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

// accounts: roles anyone can get that do more than read, open registration,
// listed accounts (new, outside the known domains, from abroad, unused,
// gone from the staff), capabilities outside roles, and API credentials.
func (c *checker) accounts() {
	s, prev := c.in.Facts.Site, c.in.Prev
	c.registration(s)
	var clients []string
	if c.in.Repo != nil {
		clients = c.in.Repo.ClientDomains
	}
	known := append(slices.Clone(c.p.StaffDomains), clients...)
	if len(known) == 0 {
		c.info("no staff or client email domains configured: email domains not checked")
	}
	if c.in.Geo == nil {
		c.info("no GeoIP database: session countries not checked (wp-data-audit geoip-update)")
	} else if len(c.p.AllowedCountries) == 0 {
		c.info("no allowed countries configured: session countries not checked")
	}
	for _, u := range s.Users {
		who := fmt.Sprintf("user %d %q <%s> roles %s", u.ID, u.Login, u.Email, strings.Join(u.Roles, ","))
		if u.Privileged {
			roles := slices.Sorted(slices.Values(u.Roles))
			p, had := prev.user(u.ID)
			changed := prev != nil && (!had || !p.Privileged || !slices.Equal(p.Roles, roles))
			msg := "account with a role the public can't get"
			if changed {
				msg = "new account with a role the public can't get, or its roles changed"
			}
			if len(known) > 0 && !domainIn(u.Email, known) {
				msg += "; email domain outside the staff and client domains"
			}
			c.flag(Flag{ID: fmt.Sprintf("user:%d:%s", u.ID, short(u.Email, strings.Join(roles, ","))), Severity: sev(changed), Kind: KindUser,
				Message: msg, Untrusted: who + ", registered " + u.Registered})
			c.sessions(u, who)
			c.dormant(u, who, s.WPVersion)
			c.leaver(u, who)
		}
		if len(u.ExtraCaps) > 0 {
			caps := slices.Sorted(slices.Values(u.ExtraCaps))
			c.flag(Flag{ID: fmt.Sprintf("caps:%d:%s", u.ID, short(caps...)), Severity: Urgent, Kind: KindCapabilities,
				Message:   "user holds capabilities outside their roles (role injection?)",
				Untrusted: who + "; extra: " + strings.Join(caps, ", ")})
		}
		for _, p := range u.AppPasswords {
			c.flag(Flag{ID: "app-password:" + idPart(p.UUID), Severity: sev(prev != nil && !prev.hasAppPassword(p.UUID)), Kind: KindAppPassword,
				Message:   "application password",
				Untrusted: fmt.Sprintf("%s; name %q, created %s, last used %s from %s", who, p.Name, ts(p.Created), ts(p.LastUsed), p.LastIP)})
		}
	}
	for _, k := range s.WooKeys {
		isNew := prev != nil && !prev.hasWooKey(k)
		c.flag(Flag{ID: fmt.Sprintf("woo-key:%d:%d:%s", k.Blog, k.ID, idPart(k.TruncatedKey)), Severity: sev(isNew && k.Permissions != "read"), Kind: KindWooKey,
			Message:   "WooCommerce REST API key",
			Untrusted: fmt.Sprintf("%s access, user %d, %q, last access %s", k.Permissions, k.UserID, k.Description, k.LastAccess)})
	}
}

// registration: a public role whose users are only counted mustn't grant
// more than reading; registration open with a role that does is urgent.
func (c *checker) registration(s *SiteFacts) {
	for _, role := range slices.Sorted(maps.Keys(s.PublicRoleCaps)) {
		caps := slices.Sorted(slices.Values(s.PublicRoleCaps[role]))
		if !readOnly(caps) {
			c.flag(Flag{ID: "public-role:" + idPart(role) + ":" + short(caps...), Severity: Urgent, Kind: KindPublicRole,
				Message:   "a role anyone can get can do more than read; its users aren't listed",
				Untrusted: role + ": " + strings.Join(caps, ", ")})
		}
	}
	reg := s.Registration
	if !reg.Open {
		return
	}
	harmless := readOnly(reg.RoleCaps)
	msg := "anyone can register"
	if !harmless {
		msg += ", and new users get a role that can do more than read"
	}
	c.flag(Flag{ID: "registration:" + idPart(reg.Role), Severity: sev(!harmless), Kind: KindRegistration,
		Message: msg, Untrusted: "default role " + reg.Role + ": " + strings.Join(reg.RoleCaps, ", ")})
}

// readOnly reports whether caps grant no more than reading.
func readOnly(caps []string) bool {
	return !slices.ContainsFunc(caps, func(cap string) bool { return cap != "read" && cap != "level_0" })
}

// sessions: one flag per account and country outside the allowed list.
func (c *checker) sessions(u User, who string) {
	if c.in.Geo == nil || len(c.p.AllowedCountries) == 0 {
		return
	}
	seen := map[string]bool{}
	for _, s := range u.Sessions {
		if c.allowedIP(s.IP) {
			continue
		}
		cc := c.in.Geo.Country(s.IP)
		if cc == "" || slices.Contains(c.p.AllowedCountries, cc) || seen[cc] {
			continue
		}
		seen[cc] = true
		c.flag(Flag{ID: fmt.Sprintf("session:%d:%s", u.ID, cc), Severity: Review, Kind: KindSession,
			Message:   "login session from a country outside the allowed list: " + cc,
			Untrusted: fmt.Sprintf("%s; IP %s, logged in %s, %s", who, s.IP, ts(s.Login), s.UA)})
	}
}

// dormant: a listed account with no sign of use in DormantAfter. With none
// on record, a phpass hash on 6.8+ means no password login since 6.8.
func (c *checker) dormant(u User, who, wpVersion string) {
	now := c.now()
	registered, _ := time.Parse("2006-01-02 15:04:05", u.Registered)
	old := !registered.IsZero() && now.Sub(registered) > DormantAfter
	seen := c.seen[u.ID]
	switch {
	case seen > 0 && now.Sub(time.Unix(seen, 0)) > DormantAfter:
		c.flag(Flag{ID: fmt.Sprintf("dormant:%d", u.ID), Severity: Review, Kind: KindDormant,
			Message: "account not used in over a year: remove it or drop its role", Untrusted: who + ", last seen " + day(seen)})
	case seen == 0 && old && (u.Hash == "phpass" || u.Hash == "md5") && atLeast(wpVersion, 6, 8) && now.Sub(wp68) > DormantAfter:
		c.flag(Flag{ID: fmt.Sprintf("dormant:%d", u.ID), Severity: Review, Kind: KindDormant,
			Message:   "account with no sign of use: no session or activity on record, and its password hasn't logged in since WordPress 6.8 (April 2025); on a site with SSO this proves nothing",
			Untrusted: who + ", registered " + u.Registered})
	}
}

// leaver: a staff-domain address not on the current staff list.
func (c *checker) leaver(u User, who string) {
	if len(c.p.StaffEmails) == 0 || !domainIn(u.Email, c.p.StaffDomains) || c.staff[strings.ToLower(u.Email)] {
		return
	}
	c.flag(Flag{ID: fmt.Sprintf("leaver:%d:%s", u.ID, short(strings.ToLower(u.Email))), Severity: Review, Kind: KindLeaver,
		Message:   "staff-domain account whose address isn't on the current staff list: someone who left, an alias or a shared address",
		Untrusted: who})
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
