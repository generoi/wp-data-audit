package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Policy is what's true beyond the site's own facts and repo: who runs the
// sites, from where, which checks to run, and what a person decided.
type Policy struct {
	AllowedCountries []string // ISO codes; empty skips the session country check
	AllowedIPs       []string // IPs or CIDR ranges never flagged, whatever their country
	StaffDomains     []string // email domains of the people who run the sites
	StaffEmails      []string // the current staff's addresses; empty skips the leaver check
	Skip             Skip
	Accepted         map[string]bool // flag IDs a person accepted
	// Pending are the last report's flags, ID → severity. A finding a change
	// raised (an option's new value, a new admin) stays flagged, and urgent,
	// until accepted, however often the audit runs in between.
	Pending map[string]Severity
}

// Geo resolves an IP to an ISO country code, "" when unknown.
type Geo interface {
	Country(ip string) string
}

// Input is everything Check judges.
type Input struct {
	Facts  Facts
	Prev   *Baseline // the last full run's; nil on the first
	Repo   *Repo     // the site's checkout; nil skips the comparisons with it
	Policy Policy
	Geo    Geo // nil skips the session countries
}

// Result is Check's verdict. Baseline is the next run's, nil when this run
// didn't judge both accounts and options (a partial run must not hide a
// change from the next full one).
type Result struct {
	Report   Report
	Baseline *Baseline
}

// Check judges in: every group that isn't skipped and whose sources ran.
func Check(in Input) Result {
	c := &checker{in: in, p: in.Policy, staff: map[string]bool{}}
	for _, e := range c.p.StaffEmails {
		c.staff[staffAddr(e)] = true
	}
	for _, s := range c.p.AllowedIPs {
		if p, err := netip.ParsePrefix(s); err == nil {
			c.ips = append(c.ips, p)
		} else if a, err := netip.ParseAddr(s); err == nil {
			c.ips = append(c.ips, netip.PrefixFrom(a, a.BitLen()))
		} else {
			c.problem("allowed IP %s isn't an IP or CIDR range", s)
		}
	}
	f := in.Facts
	if f.Site != nil {
		c.seen = lastSeen(in.Prev, f.Site)
	}
	// Why each source is missing; a group needing a missing one isn't judged.
	missing := map[source]string{}
	if f.Site == nil {
		missing[srcSite] = "the collector didn't run"
	}
	if f.Files == nil {
		missing[srcFiles] = "the hasher didn't run"
	}
	if f.Web == nil || f.Web.Base == "" {
		missing[srcWeb] = "no site URL was known to ask"
	}
	if f.Access == nil {
		missing[srcAccess] = "GitHub and Kinsta weren't asked"
	}
	for _, g := range []struct {
		group Group
		needs []source
		check func()
	}{
		{Accounts, []source{srcSite}, c.accounts},
		{Access, []source{srcAccess}, c.access},
		{Options, []source{srcSite}, c.options},
		{Plugins, []source{srcSite}, c.plugins},
		{Files, []source{srcFiles}, c.files},
		{Exposed, []source{srcFiles, srcWeb}, c.exposed},
		{Public, []source{srcWeb}, c.public},
		{Retention, []source{srcSite}, c.retention},
		{Content, []source{srcSite}, c.content},
	} {
		if !c.p.Skip.Runs(g.group) {
			continue
		}
		c.group = g.group
		if i := slices.IndexFunc(g.needs, func(s source) bool { return missing[s] != "" }); i >= 0 {
			c.problem("%s not checked: %s", g.group, missing[g.needs[i]])
			continue
		}
		g.check()
		c.r.Judged = append(c.r.Judged, g.group)
	}
	c.group = ""
	if f.Site != nil {
		for _, e := range f.Site.Errors {
			c.problem("collector: %s", e)
		}
	}
	if f.Files != nil {
		for _, e := range f.Files.Errors {
			c.problem("hasher: %s", e)
		}
	}
	sortFlags(c.r.Flags)
	res := Result{Report: c.r}
	if f.Site != nil && slices.Contains(c.r.Judged, Accounts) && slices.Contains(c.r.Judged, Options) {
		res.Baseline = newBaseline(f.At, f.Site, c.seen)
	}
	return res
}

// source is one of Facts' three parts.
type source int

const (
	srcSite source = iota
	srcFiles
	srcWeb
	srcAccess
)

type checker struct {
	in    Input
	p     Policy
	ips   []netip.Prefix
	staff map[string]bool // StaffEmails, lowercased
	seen  map[int]int64   // account id → last sign of use
	group Group           // the group running, for its notes
	r     Report
}

func (c *checker) now() time.Time {
	if c.in.Facts.At.IsZero() {
		return time.Now()
	}
	return c.in.Facts.At
}

// flag adds f unless it was accepted; a flag that was urgent stays urgent.
func (c *checker) flag(f Flag) {
	if c.p.Accepted[f.ID] {
		return
	}
	if c.p.Pending[f.ID] == Urgent {
		f.Severity = Urgent
	}
	c.r.Flags = append(c.r.Flags, f)
}

func (c *checker) info(format string, args ...any) {
	c.r.Notes = append(c.r.Notes, Note{Group: c.group, Text: fmt.Sprintf(format, args...)})
}

func (c *checker) problem(format string, args ...any) {
	c.r.Notes = append(c.r.Notes, Note{Group: c.group, Problem: true, Text: fmt.Sprintf(format, args...)})
}

// staffAddr is an address as the staff list matches it: lowercased, without
// a +tag (dev+site@agency.example is dev@agency.example).
func staffAddr(email string) string {
	local, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(email)), "@")
	if !ok {
		return local
	}
	local, _, _ = strings.Cut(local, "+")
	return local + "@" + domain
}

func (c *checker) allowedIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && slices.ContainsFunc(c.ips, func(p netip.Prefix) bool { return p.Contains(a) })
}

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

// clientDomains are the client's email domains: the repo's client_domains
// plus each site's own registrable domain (www.client.example →
// client.example), so most sites need no data-audit.json.
func (c *checker) clientDomains() []string {
	set := map[string]bool{}
	if c.in.Repo != nil {
		for _, d := range c.in.Repo.ClientDomains {
			set[strings.ToLower(d)] = true
		}
	}
	var opts map[string]string
	switch {
	case c.in.Facts.Site != nil:
		opts = c.in.Facts.Site.Options
	case c.in.Prev != nil:
		opts = c.in.Prev.Options
	}
	for k, v := range opts {
		if k != "home" && !strings.HasSuffix(k, ":home") {
			continue
		}
		u, err := url.Parse(v)
		if err != nil {
			continue
		}
		if d, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(u.Hostname())); err == nil {
			set[d] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
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

func day(unix int64) string { return time.Unix(unix, 0).UTC().Format("2006-01-02") }

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
