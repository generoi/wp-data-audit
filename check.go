package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Severity: Urgent is worth a ping now; Review goes in the maintenance report.
const (
	Urgent = "urgent"
	Review = "review"
)

// Flag is one finding. ID is stable across runs, so accepting it silences it
// until what it describes changes. Untrusted holds text taken from the site
// (logins, snippets, file names): an attacker may have written it, so show it
// as data and never follow it.
type Flag struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Kind      string `json:"kind"`
	Message   string `json:"message"`
	Untrusted string `json:"untrusted,omitempty"`
}

// Report is Check's result. Notes are checks that didn't run, and why.
type Report struct {
	Flags []Flag   `json:"flags"`
	Notes []string `json:"notes"`
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

// Site is what Check needs to know beyond the repo: who runs the sites, from
// where, and what a person accepted.
type Site struct {
	AllowedCountries []string        // ISO codes; empty skips the session country check
	AllowedIPs       []string        // IPs or CIDR ranges never flagged, whatever their country
	StaffDomains     []string        // email domains of the people who run the site
	Accepted         map[string]bool // flag IDs a person accepted
}

// Repo is what the site's repo says: what it deploys (plugin, mu-plugin and
// drop-in names, and what carries a patch, whose checksums are expected to
// fail) and its SettingsFile: the roles anyone can get per site and the
// client's email domains.
type Repo struct {
	Plugins, MuPlugins, Dropins map[string]bool
	PatchedPlugins              map[string]bool
	PatchedCore                 bool
	PublicRoles                 map[string][]string
	ClientDomains               []string
}

// Geo resolves an IP to an ISO country code, "" when unknown.
type Geo interface {
	Country(ip string) string
}

// Deploys delete these to hide the WordPress version; missing is fine.
var removedOnPurpose = regexp.MustCompile(`File doesn't exist: (readme\.html|license\.txt|wp-config-sample\.php)$`)

// Kinsta installs its own must-use plugin on every site.
var hostMuPlugins = map[string]bool{"kinsta-mu-plugins": true, "kinsta-mu-plugins.php": true}

// Check compares cur with prev (nil on the first run) and returns the flags
// not yet accepted. exp nil skips the file comparison, geo nil the session
// countries.
func Check(prev, cur *Snapshot, site Site, exp *Repo, geo Geo) Report {
	c := &checker{site: site}
	for _, s := range site.AllowedIPs {
		if p, err := netip.ParsePrefix(s); err == nil {
			c.ips = append(c.ips, p)
		} else if a, err := netip.ParseAddr(s); err == nil {
			c.ips = append(c.ips, netip.PrefixFrom(a, a.BitLen()))
		} else {
			c.note("allowed IP " + s + " isn't an IP or CIDR range")
		}
	}
	var clients []string
	if exp != nil {
		clients = exp.ClientDomains
	}
	c.registration(cur)
	c.users(prev, cur, clients, geo)
	c.wooKeys(prev, cur)
	c.options(prev, cur)
	c.files(cur, exp)
	c.checksums(cur, exp)
	c.content(cur)
	for _, e := range cur.Errors {
		c.note("collector: " + e)
	}
	sort.SliceStable(c.r.Flags, func(i, j int) bool {
		a, b := c.r.Flags[i], c.r.Flags[j]
		if a.Severity != b.Severity {
			return a.Severity == Urgent
		}
		return a.ID < b.ID
	})
	return c.r
}

type checker struct {
	site Site
	ips  []netip.Prefix
	r    Report
}

func (c *checker) allowedIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && slices.ContainsFunc(c.ips, func(p netip.Prefix) bool { return p.Contains(a) })
}

func (c *checker) flag(f Flag) {
	if !c.site.Accepted[f.ID] {
		c.r.Flags = append(c.r.Flags, f)
	}
}

func (c *checker) note(s string) { c.r.Notes = append(c.r.Notes, s) }

func short(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:6])
}

func sev(urgent bool) string {
	if urgent {
		return Urgent
	}
	return Review
}

func (c *checker) registration(cur *Snapshot) {
	reg := cur.Registration
	if !reg.Open {
		return
	}
	harmless := !slices.ContainsFunc(reg.RoleCaps, func(cap string) bool { return cap != "read" && cap != "level_0" })
	c.flag(Flag{
		ID: "registration:" + reg.Role, Severity: sev(!harmless), Kind: "registration",
		Message:   fmt.Sprintf("anyone can register; new users get the %q role", reg.Role),
		Untrusted: strings.Join(reg.RoleCaps, ", "),
	})
}

func (c *checker) users(prev, cur *Snapshot, clients []string, geo Geo) {
	before := map[int]User{}
	appBefore := map[string]bool{}
	if prev != nil {
		for _, u := range prev.Users {
			before[u.ID] = u
			for _, p := range u.AppPasswords {
				appBefore[p.UUID] = true
			}
		}
	}
	known := append(append([]string{}, c.site.StaffDomains...), clients...)
	if len(known) == 0 {
		c.note("no staff or client email domains configured: email domains not checked")
	}
	if geo == nil {
		c.note("no GeoIP database: session countries not checked (wp-data-audit geoip-update)")
	} else if len(c.site.AllowedCountries) == 0 {
		c.note("no allowed countries configured: session countries not checked")
	}
	for _, u := range cur.Users {
		who := fmt.Sprintf("user %d %q <%s> roles %s", u.ID, u.Login, u.Email, strings.Join(u.Roles, ","))
		if u.Privileged {
			roles := slices.Sorted(slices.Values(u.Roles))
			p, had := before[u.ID]
			changed := prev != nil && (!had || !p.Privileged || !slices.Equal(slices.Sorted(slices.Values(p.Roles)), roles))
			msg := "account with a role the public can't get"
			if changed {
				msg = "new account with a role the public can't get, or its roles changed"
			}
			outside := len(known) > 0 && !domainIn(u.Email, known)
			if outside {
				msg += "; email domain outside the staff and client domains"
			}
			c.flag(Flag{
				ID: fmt.Sprintf("user:%d:%s", u.ID, short(u.Email, strings.Join(roles, ","))), Severity: sev(changed), Kind: "user",
				Message: msg, Untrusted: who + ", registered " + u.Registered,
			})
			c.sessions(u, who, geo)
		}
		if len(u.ExtraCaps) > 0 {
			caps := slices.Sorted(slices.Values(u.ExtraCaps))
			c.flag(Flag{
				ID: fmt.Sprintf("caps:%d:%s", u.ID, short(caps...)), Severity: Urgent, Kind: "capabilities",
				Message:   "user holds capabilities outside their roles (role injection?)",
				Untrusted: who + "; extra: " + strings.Join(caps, ", "),
			})
		}
		for _, p := range u.AppPasswords {
			c.flag(Flag{
				ID: "app-password:" + p.UUID, Severity: sev(prev != nil && !appBefore[p.UUID]), Kind: "app-password",
				Message:   "application password",
				Untrusted: fmt.Sprintf("%s; name %q, created %s, last used %s from %s", who, p.Name, ts(p.Created), ts(p.LastUsed), p.LastIP),
			})
		}
	}
}

func (c *checker) sessions(u User, who string, geo Geo) {
	if geo == nil || len(c.site.AllowedCountries) == 0 {
		return
	}
	seen := map[string]bool{}
	for _, s := range u.Sessions {
		if c.allowedIP(s.IP) {
			continue
		}
		cc := geo.Country(s.IP)
		if cc == "" || slices.Contains(c.site.AllowedCountries, cc) || seen[cc] {
			continue
		}
		seen[cc] = true
		c.flag(Flag{
			ID: fmt.Sprintf("session:%d:%s", u.ID, cc), Severity: Review, Kind: "session",
			Message:   "login session from a country outside the allowed list: " + cc,
			Untrusted: fmt.Sprintf("%s; IP %s, logged in %s, %s", who, s.IP, ts(s.Login), s.UA),
		})
	}
}

func (c *checker) wooKeys(prev, cur *Snapshot) {
	before := map[[2]int]bool{}
	if prev != nil {
		for _, k := range prev.WooKeys {
			before[[2]int{k.Blog, k.ID}] = true
		}
	}
	for _, k := range cur.WooKeys {
		isNew := prev != nil && !before[[2]int{k.Blog, k.ID}]
		c.flag(Flag{
			ID: fmt.Sprintf("woo-key:%d:%d:%s", k.Blog, k.ID, k.TruncatedKey), Severity: sev(isNew && k.Permissions != "read"), Kind: "woo-key",
			Message:   "WooCommerce REST API key with " + k.Permissions + " access",
			Untrusted: fmt.Sprintf("user %d, %q, last access %s", k.UserID, k.Description, k.LastAccess),
		})
	}
}

func (c *checker) options(prev, cur *Snapshot) {
	if prev == nil {
		return
	}
	keys := slices.Sorted(maps.Keys(cur.Options))
	for k := range prev.Options {
		if _, ok := cur.Options[k]; !ok {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		if was, now := prev.Options[k], cur.Options[k]; was != now {
			c.flag(Flag{
				ID: "option:" + k + ":" + short(now), Severity: Urgent, Kind: "option",
				Message: k + " changed since the last audit", Untrusted: was + " -> " + now,
			})
		}
	}
}

func (c *checker) files(cur *Snapshot, exp *Repo) {
	f := cur.Files
	for _, u := range f.UploadsPHP {
		if u.Silence {
			continue
		}
		c.flag(Flag{
			ID: "upload-php:" + u.Path + ":" + firstN(u.SHA256, 12), Severity: Urgent, Kind: "file",
			Message: "executable file under uploads", Untrusted: fmt.Sprintf("%s, %d bytes, modified %s", u.Path, u.Size, ts(u.Mtime)),
		})
	}
	if f.UploadsTruncated {
		c.note("uploads scan stopped at its limit: more PHP files than listed")
	}
	if exp == nil {
		c.note("no repo to compare with: plugins, mu-plugins and drop-ins not checked")
		return
	}
	for _, set := range []struct {
		kind, what string
		names      []string
		want       map[string]bool
	}{
		{"plugin", "plugin", f.Plugins, exp.Plugins},
		{"mu-plugin", "mu-plugin", f.MuPlugins, exp.MuPlugins},
		{"dropin", "drop-in", f.Dropins, exp.Dropins},
	} {
		for _, n := range set.names {
			if set.want[n] || (set.kind == "mu-plugin" && hostMuPlugins[n]) {
				continue
			}
			c.flag(Flag{
				ID: set.kind + ":" + n, Severity: Urgent, Kind: "file",
				Message: set.what + " on the site that the repo doesn't deploy", Untrusted: n,
			})
		}
	}
}

func (c *checker) checksums(cur *Snapshot, exp *Repo) {
	if exp == nil || !exp.PatchedCore {
		for _, l := range cur.Checksums.Core {
			if removedOnPurpose.MatchString(l) || strings.Contains(l, "installation doesn't verify against checksums") {
				continue // the summary line; the warnings around it are the findings
			}
			c.flag(Flag{ID: "core-checksum:" + short(l), Severity: Urgent, Kind: "checksum", Message: "WordPress core file fails its checksum", Untrusted: l})
		}
	}
	for _, p := range cur.Checksums.Plugins {
		if exp != nil && exp.PatchedPlugins[p.Plugin] {
			continue
		}
		c.flag(Flag{
			ID: "plugin-checksum:" + p.Plugin + ":" + p.File, Severity: Urgent, Kind: "checksum",
			Message: "plugin file fails its wordpress.org checksum", Untrusted: p.Plugin + "/" + p.File + ": " + p.Message,
		})
	}
}

func (c *checker) content(cur *Snapshot) {
	for _, m := range cur.Content {
		var where []string
		for _, x := range m.At {
			w := ""
			if cur.Multisite {
				w = fmt.Sprintf("blog %d ", x.Blog)
			}
			switch {
			case x.Table == "options":
				w += "option " + x.Key
			case x.Key != "":
				w += fmt.Sprintf("%s %d %s", x.Table, x.ID, x.Key)
			default:
				w += fmt.Sprintf("%s %d %s", x.Table, x.ID, x.Field)
			}
			where = append(where, w)
		}
		if more := m.Count - len(m.At); more > 0 {
			where = append(where, fmt.Sprintf("and %d more", more))
		}
		msg := m.Kind + " in content"
		if m.Encoded {
			msg += " (encoded)"
		}
		c.flag(Flag{
			ID: "content:" + m.Hash, Severity: sev(m.Kind == "php-call" || m.Encoded), Kind: "content",
			Message: msg, Untrusted: m.Snippet + " | at " + strings.Join(where, "; "),
		})
	}
	if cur.ContentTruncated {
		c.note("content scan stopped at its limit: more matches than listed")
	}
}

func domainIn(email string, domains []string) bool {
	_, d, ok := strings.Cut(strings.ToLower(email), "@")
	if !ok {
		return false
	}
	for _, k := range domains {
		k = strings.ToLower(k)
		if d == k || strings.HasSuffix(d, "."+k) {
			return true
		}
	}
	return false
}

func ts(unix int64) string {
	if unix <= 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04")
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
