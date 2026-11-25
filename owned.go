package audit

import (
	"path"
	"regexp"
	"strings"
)

// pluginOwn is what a plugin adds of its own while it is active, which the
// checks would otherwise take for tampering: capabilities it gives users
// (a trailing * is a prefix), the prefixes of its scheduled hooks, and the
// compiled PHP it writes under uploads (a pattern of the path below uploads).
type pluginOwn struct {
	caps, hooks []string
	uploadsPHP  *regexp.Regexp
}

// wpmlTwig is WPML's Twig template cache: cache/wpml/twig/<ab>/<ab…>.php,
// the file named by its sha256, its folder by the name's first two digits
// (checked in ownedPHP).
var wpmlTwig = regexp.MustCompile(`^cache/wpml/twig/([0-9a-f]{2})/([0-9a-f]{64})\.php$`)

// pluginsOwn are the plugins whose own additions are known, by folder.
var pluginsOwn = map[string]pluginOwn{
	"sitepress-multilingual-cms": {caps: []string{"translate", "manage_translations", "wpml_*"}, hooks: []string{"wpml_", "icl_"}, uploadsPHP: wpmlTwig},
	"wpml-string-translation":    {caps: []string{"wpml_*"}, hooks: []string{"wpml_"}},
	"wordpress-seo":              {hooks: []string{"wpseo"}},
	"wordpress-seo-premium":      {hooks: []string{"wpseo"}},
	"woocommerce":                {hooks: []string{"woocommerce_", "wc_"}},
	"gravityforms":               {hooks: []string{"gravityforms_", "gform_"}},
	"redirection":                {hooks: []string{"redirection_"}},
	"seoaiwp":                    {hooks: []string{"seoaic_", "seoaiwp_"}},
	"ns-cloner-site-copier":      {hooks: []string{"ns_cloner"}},
}

// activeFolders are the folders of the plugins active on blog ("" for any
// blog), network-activated ones included.
func (c *checker) activeFolders(blog string) map[string]bool {
	out := map[string]bool{}
	s := c.in.Facts.Site
	if s == nil {
		return out
	}
	for b, files := range s.ActivePlugins {
		if blog != "" && b != blog && b != "network" {
			continue
		}
		for _, f := range files {
			out[strings.SplitN(f, "/", 2)[0]] = true
		}
	}
	return out
}

// blogTag is a multisite's "<blog id>:" before a capability from another site.
var blogTag = regexp.MustCompile(`^[0-9]+:`)

// ownedCap reports whether an active plugin gives cap to users itself.
func ownedCap(active map[string]bool, cap string) bool {
	cap = blogTag.ReplaceAllString(cap, "")
	for folder, o := range pluginsOwn {
		if !active[folder] {
			continue
		}
		for _, p := range o.caps {
			if cap == p || strings.HasSuffix(p, "*") && strings.HasPrefix(cap, strings.TrimSuffix(p, "*")) {
				return true
			}
		}
	}
	return false
}

// ownedHook reports whether an active plugin schedules hook itself: its
// prefix is the plugin's. The same hook with the plugin inactive is flagged.
func ownedHook(active map[string]bool, hook string) bool {
	for folder, o := range pluginsOwn {
		if !active[folder] {
			continue
		}
		for _, p := range o.hooks {
			if strings.HasPrefix(hook, p) {
				return true
			}
		}
	}
	return false
}

// ownedPHP is the active plugin whose compiled cache rest (below uploads) is,
// "" for none: only the exact shape of that cache counts.
func ownedPHP(active map[string]bool, rest string) string {
	for folder, o := range pluginsOwn {
		if !active[folder] || o.uploadsPHP == nil {
			continue
		}
		m := o.uploadsPHP.FindStringSubmatch(rest)
		if m == nil {
			continue
		}
		if o.uploadsPHP == wpmlTwig && !strings.HasPrefix(m[2], m[1]) {
			continue
		}
		return folder
	}
	return ""
}

// linkedDoc reports whether rest (below uploads) is a file the site links to
// from published content or post fields (the collector's linked_uploads).
func (c *checker) linkedDoc(rest string) bool {
	s := c.in.Facts.Site
	if s == nil || len(s.LinkedUploads) == 0 {
		return false
	}
	return s.linked()[path.Clean(rest)]
}
