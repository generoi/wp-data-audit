package audit

import (
	"maps"
	"slices"
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
}
