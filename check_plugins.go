package audit

import (
	"maps"
	"slices"
	"strings"
	"time"
)

// staleAfter is how long without a wordpress.org release a plugin counts as
// abandoned.
const staleAfter = 2 * 365 * 24 * time.Hour

// plugins: installed but active on no site (remove it from composer.json),
// activated or deactivated since the last audit, and wordpress.org's
// closed or long-unreleased ones.
func (c *checker) plugins() {
	s := c.in.Facts.Site
	active := map[string]bool{}
	for _, files := range s.ActivePlugins {
		for _, f := range files {
			active[pluginName(f)] = true
		}
	}
	for _, p := range slices.Sorted(slices.Values(s.InstalledPlugins)) {
		if !active[p] {
			c.flag(Flag{ID: "plugin-inactive:" + idPart(p), Severity: Review, Kind: KindPlugin,
				Message: "plugin installed but active on no site: remove it from composer.json (an inactive plugin's files can still be attacked)", Untrusted: p})
		}
	}
	if prev := c.in.Prev; prev != nil && prev.Plugins != nil {
		for _, blog := range slices.Sorted(maps.Keys(s.ActivePlugins)) {
			was, ok := prev.Plugins[blog]
			now := s.ActivePlugins[blog]
			for _, change := range []struct {
				name     string
				from, to []string
			}{{"activated", was, now}, {"deactivated", now, was}} {
				for _, f := range change.to {
					id := "plugin-" + change.name + ":" + blog + ":" + idPart(pluginName(f))
					if (!ok || slices.Contains(change.from, f)) && c.p.Pending[id] == "" {
						continue
					}
					if change.name == "deactivated" && slices.Contains(now, f) {
						continue // pending, but active again
					}
					c.flag(Flag{ID: id, Severity: Review, Kind: KindPlugin,
						Message: "plugin " + change.name + " since the last audit", Untrusted: f + " (site " + blog + ")"})
				}
			}
		}
	}
	c.wporg()
}

// wporg: the repo's wordpress.org plugins that wordpress.org closed (urgent
// when for security) or hasn't seen a release of in staleAfter.
func (c *checker) wporg() {
	info := c.in.Facts.WPOrg
	if info == nil {
		c.info("wordpress.org wasn't asked about the plugins (no repo, or none from wordpress.org)")
		return
	}
	failed := 0
	for _, slug := range slices.Sorted(maps.Keys(info)) {
		p := info[slug]
		switch {
		case p.Err != "":
			failed++
		case p.Closed:
			urgent := strings.Contains(strings.ToLower(p.Reason), "security")
			c.flag(Flag{ID: "plugin-closed:" + idPart(slug), Severity: sev(urgent), Kind: KindPlugin,
				Message: "plugin closed on wordpress.org: no more updates, replace it", Untrusted: slug + " (" + strings.TrimSpace(p.Reason+" "+p.ClosedDate) + ")"})
		default:
			t, err := time.Parse("2006-01-02", p.LastUpdated)
			if err == nil && c.now().Sub(t) > staleAfter {
				c.flag(Flag{ID: "plugin-stale:" + idPart(slug) + ":" + p.LastUpdated, Severity: Review, Kind: KindPlugin,
					Message: "no release on wordpress.org in over two years: likely abandoned", Untrusted: slug + " (last " + p.LastUpdated + ")"})
			}
		}
	}
	if failed > 0 {
		c.problem("wordpress.org couldn't be asked about %d plugin(s)", failed)
	}
}

// pluginName is an active_plugins entry's folder ("akismet/akismet.php" →
// akismet), or the file of a single-file plugin.
func pluginName(file string) string {
	if dir, _, ok := strings.Cut(file, "/"); ok {
		return dir
	}
	return file
}
