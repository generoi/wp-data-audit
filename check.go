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
	// Pending are the last report's flags, ID → severity. A change caught by
	// comparing with the previous snapshot (an option's new value, a new
	// admin) stays flagged, and urgent, until accepted, however often the
	// audit runs in between.
	Pending map[string]string
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
	// Revision is the checkout's commit; Local its composer install's PHP
	// files hashed like the server's (nil, with LocalWhy, when there's none).
	Revision string
	Local    map[string]string
	LocalWhy string
}

// Geo resolves an IP to an ISO country code, "" when unknown.
type Geo interface {
	Country(ip string) string
}

// Deploys delete these to hide the WordPress version; missing is fine.
var removedOnPurpose = regexp.MustCompile(`File doesn't exist: (readme\.html|license\.txt|wp-config-sample\.php)$`)

// coreFileLine is a core verify-checksums warning about a file.
var coreFileLine = regexp.MustCompile(`File (doesn't verify against checksum|should not exist|doesn't exist): `)

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
	if !c.files(cur, exp) { // compared with the deployed commit: wordpress.org's checksums add nothing
		c.checksums(cur, exp)
	}
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
	if c.site.Accepted[f.ID] {
		return
	}
	if c.site.Pending[f.ID] == Urgent {
		f.Severity = Urgent
	}
	c.r.Flags = append(c.r.Flags, f)
}

func (c *checker) note(s string) { c.r.Notes = append(c.r.Notes, s) }

func short(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:6])
}

var plainID = regexp.MustCompile(`^[A-Za-z0-9._@/:+-]{1,120}$`)

// idPart is site text (a file or plugin name) as part of a flag ID: as is
// when plain, else a hash. IDs are shown outside the untrusted quotes and
// typed back to accept, so a name with a newline or an instruction in it
// must not become one.
func idPart(s string) string {
	if plainID.MatchString(s) {
		return s
	}
	return "h" + short(s)
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
	msg := "anyone can register"
	if !harmless {
		msg += ", and new users get a role that can do more than read"
	}
	c.flag(Flag{
		ID: "registration:" + idPart(reg.Role), Severity: sev(!harmless), Kind: "registration",
		Message: msg, Untrusted: "default role " + reg.Role + ": " + strings.Join(reg.RoleCaps, ", "),
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
				ID: "app-password:" + idPart(p.UUID), Severity: sev(prev != nil && !appBefore[p.UUID]), Kind: "app-password",
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
			ID: fmt.Sprintf("woo-key:%d:%d:%s", k.Blog, k.ID, idPart(k.TruncatedKey)), Severity: sev(isNew && k.Permissions != "read"), Kind: "woo-key",
			Message:   "WooCommerce REST API key",
			Untrusted: fmt.Sprintf("%s access, user %d, %q, last access %s", k.Permissions, k.UserID, k.Description, k.LastAccess),
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
		was, now := prev.Options[k], cur.Options[k]
		id := "option:" + idPart(k) + ":" + short(now)
		if was != now || c.site.Pending[id] != "" {
			msg := "changed since the last audit"
			if was == now {
				msg = "changed in an earlier audit, not accepted yet"
			}
			c.flag(Flag{ID: id, Severity: Urgent, Kind: "option", Message: "site option " + msg, Untrusted: k + ": " + was + " -> " + now})
		}
	}
}

// files judges the hasher's file list: PHP under uploads; plugins,
// mu-plugins and drop-ins the repo doesn't deploy; and every other PHP file
// against a composer install of the deployed commit. It reports whether that
// comparison ran (the wordpress.org checksums are then redundant).
func (c *checker) files(cur *Snapshot, exp *Repo) (compared bool) {
	rel := cur.Release
	if rel == nil {
		c.note("the hasher didn't run: no PHP file was checked")
		return false
	}
	for _, e := range rel.Errors {
		c.note("hasher: " + e)
	}
	if rel.Truncated {
		c.note("the hasher stopped at its file limit: not every PHP file was checked")
	}
	content := rel.Content
	uploads := content + "/uploads/"
	paths := slices.Sorted(maps.Keys(rel.Files))
	units := map[string]bool{} // undeployed plugins etc., flagged once as a whole
	for _, p := range paths {
		v := rel.Files[p]
		if rest, ok := strings.CutPrefix(p, uploads); ok {
			if !strings.HasSuffix(v, ":silence") {
				c.flag(Flag{
					ID: "upload-php:" + idPart(rest) + ":" + idPart(fileHash(v)), Severity: Urgent, Kind: "file",
					Message: "executable file under uploads", Untrusted: rest + " (" + v + ")",
				})
			}
			continue
		}
		if exp == nil {
			continue
		}
		kind, name := placed(p, content)
		want := map[string]map[string]bool{"plugin": exp.Plugins, "mu-plugin": exp.MuPlugins, "dropin": exp.Dropins}[kind]
		if want == nil || want[name] || (kind == "mu-plugin" && hostMuPlugins[name]) || units[kind+name] {
			continue
		}
		units[kind+name] = true
		c.flag(Flag{
			ID: kind + ":" + idPart(name), Severity: Urgent, Kind: "file",
			Message: kind + " on the site that the repo doesn't deploy", Untrusted: name,
		})
	}
	switch {
	case exp == nil:
		c.note("no repo to compare with: plugins and PHP files not checked")
		return false
	case exp.Local == nil:
		c.note("PHP files not compared with the deployed commit: " + exp.LocalWhy)
		return false
	case rel.Revision != "" && exp.Revision != "" && !strings.HasPrefix(exp.Revision, rel.Revision) && !strings.HasPrefix(rel.Revision, exp.Revision):
		c.note(fmt.Sprintf("PHP files not compared: production runs %s, the checkout is at %.12s", firstN(rel.Revision, 12), exp.Revision))
		return false
	case rel.Revision == "":
		c.note("the deployed commit is unknown (no REVISION file, no deploy run found): PHP files compared with the checkout as it is")
	}

	// One flag per package or theme, its ID covering every differing file, so
	// accepting it holds until any of them changes again.
	type diff struct{ changed, extra []string }
	diffs := map[string]*diff{}
	skipped := map[string]int{}
	for _, p := range paths {
		if strings.HasPrefix(p, uploads) {
			continue
		}
		kind, name := placed(p, content)
		if units[kind+name] || (kind == "mu-plugin" && hostMuPlugins[name]) {
			continue // flagged as a whole, or the host's
		}
		u := unit(p, content)
		lv, ok := exp.Local[p]
		switch {
		case ok && fileHash(lv) == fileHash(rel.Files[p]):
			continue
		case u == content+"/languages":
			skipped["translation files WordPress updates itself (languages)"]++
			continue
		case !ok && (u == content+"/cache" || strings.Contains(p, "/storage/framework/")):
			skipped["caches the site compiles itself (cache/, Acorn's storage/framework/)"]++
			continue
		case !ok && strings.Contains(p, "/build/"):
			skipped["built files the checkout hasn't built (build/)"]++
			continue
		}
		d := diffs[u]
		if d == nil {
			d = &diff{}
			diffs[u] = d
		}
		if ok {
			d.changed = append(d.changed, p)
		} else {
			d.extra = append(d.extra, p)
		}
	}
	for _, u := range slices.Sorted(maps.Keys(diffs)) {
		d := diffs[u]
		var sig []string
		for _, p := range append(slices.Clone(d.changed), d.extra...) {
			sig = append(sig, p+"="+fileHash(rel.Files[p]))
		}
		slices.Sort(sig)
		all := append(slices.Clone(d.changed), d.extra...)
		if len(all) > 5 {
			all = append(all[:5], fmt.Sprintf("and %d more", len(all)-5))
		}
		c.flag(Flag{
			ID: "release:" + idPart(u) + ":" + short(sig...), Severity: Urgent, Kind: "release",
			Message:   fmt.Sprintf("PHP files differ from the deployed commit: %d changed, %d not in the release", len(d.changed), len(d.extra)),
			Untrusted: u + ": " + strings.Join(all, ", "),
		})
	}
	for what, n := range skipped {
		c.note(fmt.Sprintf("%d PHP file(s) not compared: %s", n, what))
	}
	return true
}

// fileHash is the hash part of a hasher value.
func fileHash(v string) string {
	h, _, _ := strings.Cut(v, ":")
	return h
}

// placed says what p is under content: a plugin, mu-plugin or drop-in and
// its name (its folder, or the file for a single-file one); "" for the rest.
func placed(p, content string) (kind, name string) {
	rest, ok := strings.CutPrefix(p, content+"/")
	if !ok {
		return "", ""
	}
	parts := strings.SplitN(rest, "/", 3)
	switch {
	case len(parts) == 1:
		return "dropin", parts[0]
	case parts[0] == "plugins" && parts[1] != "index.php":
		return "plugin", parts[1]
	case parts[0] == "mu-plugins" && parts[1] != "index.php":
		return "mu-plugin", parts[1]
	}
	return "", ""
}

// unit is what a differing file belongs to, one flag per unit: a plugin,
// mu-plugin, theme or vendor package, core, or a content subfolder.
func unit(p, content string) string {
	parts := strings.Split(p, "/")
	if rest, ok := strings.CutPrefix(p, content+"/"); ok {
		sub := strings.Split(rest, "/")
		switch {
		case len(sub) == 1:
			return p
		case (sub[0] == "plugins" || sub[0] == "mu-plugins" || sub[0] == "themes") && len(sub) > 2:
			return content + "/" + sub[0] + "/" + sub[1]
		}
		return content + "/" + sub[0]
	}
	switch {
	case parts[0] == "vendor" && len(parts) > 3:
		return strings.Join(parts[:3], "/")
	case parts[0] == "web" && len(parts) > 1 && parts[1] == "wp", parts[0] == "wp-includes", parts[0] == "wp-admin":
		return "core"
	}
	return parts[0]
}

func (c *checker) checksums(cur *Snapshot, exp *Repo) {
	if exp == nil || !exp.PatchedCore {
		for _, l := range cur.Checksums.Core {
			switch {
			case removedOnPurpose.MatchString(l), strings.Contains(l, "installation doesn't verify against checksums"):
				// deliberate, or the summary line: the file warnings around it are the findings
			case coreFileLine.MatchString(l):
				c.flag(Flag{ID: "core-checksum:" + short(l), Severity: Urgent, Kind: "checksum", Message: "WordPress core file fails its checksum", Untrusted: l})
			default: // the check itself failed (no checksums from wordpress.org, say): not a finding
				c.note("core checksums: " + l)
			}
		}
	}
	for _, p := range cur.Checksums.Plugins {
		if exp != nil && exp.PatchedPlugins[p.Plugin] {
			continue
		}
		c.flag(Flag{
			ID: "plugin-checksum:" + idPart(p.Plugin) + ":" + idPart(p.File), Severity: Urgent, Kind: "checksum",
			Message: "plugin file fails its wordpress.org checksum", Untrusted: p.Plugin + "/" + p.File + ": " + p.Message,
		})
	}
	if n := cur.Checksums.PluginsSkipped; n > 0 {
		c.note(fmt.Sprintf("%d plugin(s) have no wordpress.org checksums (premium or custom), so their files weren't verified", n))
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
