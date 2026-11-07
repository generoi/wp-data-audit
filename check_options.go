package audit

import (
	"cmp"
	"maps"
	"slices"
	"strings"
)

// options: a watched option (siteurl, home, admin_email, per site) changed
// since the last full run, flagged until accepted.
func (c *checker) options() {
	prev := c.in.Prev
	if prev == nil {
		return
	}
	cur := c.in.Facts.Site.Options
	keys := slices.Sorted(maps.Keys(cur))
	for k := range prev.Options {
		if _, ok := cur[k]; !ok {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		was, now := prev.Options[k], cur[k]
		id := "option:" + idPart(k) + ":" + short(now)
		if was == now && c.p.Pending[id] == "" {
			continue
		}
		msg := "site option changed since the last audit"
		if was == now {
			msg = "site option changed in an earlier audit, not accepted yet"
		}
		c.flag(Flag{ID: id, Severity: Urgent, Kind: KindOption, Message: msg, Untrusted: k + ": " + was + " -> " + now})
	}
	c.sensitive()
	c.cron()
}

// sensitive: a sensitive option (theme, upload paths, role definitions, a
// payment gateway's or SMTP plugin's settings) whose value changed since the
// last audit. Only hashes are compared: the values are never collected.
// Role definitions and payment settings are urgent: a skimmer or a role
// handed every capability starts there.
func (c *checker) sensitive() {
	prev := c.in.Prev
	if prev == nil || prev.Sensitive == nil {
		return
	}
	cur := c.in.Facts.Site.Sensitive
	keys := slices.Sorted(maps.Keys(cur))
	for k := range prev.Sensitive {
		if _, ok := cur[k]; !ok {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		was, now := prev.Sensitive[k], cur[k]
		id := "sensitive:" + idPart(k) + ":" + cmp.Or(now, "gone")
		if was == now && c.p.Pending[id] == "" {
			continue
		}
		what := "changed"
		switch {
		case was == "":
			what = "added"
		case now == "":
			what = "removed"
		}
		name := k // without the blog tag ("2:user_roles")
		if _, n, ok := strings.Cut(k, ":"); ok {
			name = n
		}
		urgent := name == "user_roles" || strings.HasSuffix(name, "_settings") && strings.HasPrefix(name, "woocommerce_")
		c.flag(Flag{ID: id, Severity: sev(urgent), Kind: KindOption,
			Message: "sensitive option " + what + " since the last audit (its value isn't collected: look at it in the site)", Untrusted: k})
	}
}

// cron: a scheduled hook on a site that the last audit didn't see, flagged
// until accepted. Backdoors often schedule themselves to come back.
func (c *checker) cron() {
	prev := c.in.Prev
	if prev == nil || prev.Cron == nil {
		return
	}
	for _, blog := range slices.Sorted(maps.Keys(c.in.Facts.Site.Cron)) {
		was, ok := prev.Cron[blog]
		for _, hook := range c.in.Facts.Site.Cron[blog] {
			id := "cron:" + blog + ":" + idPart(hook)
			if (!ok || slices.Contains(was, hook)) && c.p.Pending[id] == "" {
				continue // a site the last audit didn't have: its hooks aren't news
			}
			c.flag(Flag{ID: id, Severity: Review, Kind: KindCron,
				Message: "scheduled hook new since the last audit", Untrusted: hook + " (site " + blog + ")"})
		}
	}
}
