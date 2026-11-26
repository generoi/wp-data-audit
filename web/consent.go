package web

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

type marker struct {
	name string
	re   *regexp.Regexp
}

// trackers are the scripts that track a visitor once they run.
var trackers = []marker{
	{"gtm", regexp.MustCompile(`(?i)googletagmanager\.com/gtm\.js`)},
	{"gtag", regexp.MustCompile(`(?i)googletagmanager\.com/gtag/js`)},
	{"ga", regexp.MustCompile(`(?i)google-analytics\.com/(?:analytics|ga)\.js`)},
	{"matomo", regexp.MustCompile(`(?i)/container_[a-z0-9]+\.js|/matomo\.js|/piwik\.js`)},
	{"meta-pixel", regexp.MustCompile(`(?i)connect\.facebook\.net/[^"'\s]*/fbevents\.js`)},
	{"hotjar", regexp.MustCompile(`(?i)static\.hotjar\.com`)},
	{"clarity", regexp.MustCompile(`(?i)clarity\.ms/tag`)},
	{"linkedin", regexp.MustCompile(`(?i)snap\.licdn\.com`)},
}

// google are the trackers consent mode holds back: a consent default before
// them is enough. The others only wait for a consent tool.
var google = []string{"gtm", "gtag", "ga"}

// consentTools are the consent tools the fleet uses or meets.
var consentTools = regexp.MustCompile(`(?i)genero-cmp|consent\.cookiebot\.(?:com|eu)|cmplz|cdn-cookieyes\.com|cdn\.cookielaw\.org|otSDKStub|usercentrics\.eu`)

// consentMode is a consent default, gtag's or a dataLayer push's.
var consentMode = regexp.MustCompile(`(?i)(?:gtag\(\s*|\[\s*)["']consent["']\s*,\s*["']default["']`)

// matomoConsent is Matomo told to wait for consent or not to set cookies.
var matomoConsent = regexp.MustCompile(`["'](?:requireConsent|requireCookieConsent|disableCookies)["']`)

// inactive are blocks that don't run: scripts a consent tool parked as
// text/plain or JSON (until consent), noscript fallbacks, and link tags
// (dns-prefetch and preconnect hints name a tracker's host, load nothing).
var inactive = regexp.MustCompile(`(?is)<script\b[^>]*\btype=["']?(?:text/plain|application/(?:ld\+)?json)[^>]*>.*?</script>|<noscript\b.*?</noscript>|<link\b[^>]*>`)

var (
	gtmID           = regexp.MustCompile(`GTM-[A-Z0-9]{4,10}`)
	matomoContainer = regexp.MustCompile(`(?i)(?:https?:)?//[^"'\s]+/container_[a-z0-9]+\.js`)
	// containerConsent is a consent tool a GTM container loads itself.
	// Cookiebot's template joins its domain's ending on at runtime.
	containerConsent = regexp.MustCompile(`(?i)consent\.cookiebot\.|cdn-cookieyes\.com|cdn\.cookielaw\.org|usercentrics\.eu|cmplz`)
)

// earlyTrackers are the trackers a page starts before any consent: a Google
// tag before the first consent default or consent tool, any other before the
// first consent tool. Each tracker's first appearance counts.
func earlyTrackers(page []byte) []string {
	page = inactive.ReplaceAll(page, nil)
	tool := firstAt(consentTools, page)
	mode := firstAt(consentMode, page)
	matomo := firstAt(matomoConsent, page)
	var early []string
	for _, t := range trackers {
		at := firstAt(t.re, page)
		if at < 0 {
			continue
		}
		guard := tool
		if slices.Contains(google, t.name) {
			guard = earliest(tool, mode)
		}
		if t.name == "matomo" {
			guard = earliest(guard, matomo)
		}
		if guard < 0 || at < guard {
			early = append(early, t.name)
		}
	}
	return early
}

// trackers are page's early trackers, less those whose own container waits
// for consent: a GTM container that loads a consent tool, a Matomo container
// that is cookieless or requires consent. Containers are read from where the
// visitor's browser reads them, at most three of each.
func (p *prober) trackers(page []byte) []string {
	early := earlyTrackers(page)
	if slices.Contains(early, "gtm") && p.gtmWaits(page) {
		early = slices.DeleteFunc(early, func(t string) bool { return t == "gtm" })
	}
	if slices.Contains(early, "matomo") && p.matomoWaits(page) {
		early = slices.DeleteFunc(early, func(t string) bool { return t == "matomo" })
	}
	return early
}

func (p *prober) gtmWaits(page []byte) bool {
	for _, id := range firstUnique(gtmID.FindAll(page, -1), 3) {
		if b := p.container("https://www.googletagmanager.com/gtm.js?id=" + id); containerConsent.Match(b) {
			return true
		}
	}
	return false
}

// matomoWaits: every container found is cookieless (no configuration with
// cookies on) or requires consent.
func (p *prober) matomoWaits(page []byte) bool {
	urls := firstUnique(matomoContainer.FindAll(page, -1), 3)
	if len(urls) == 0 {
		return false
	}
	for _, u := range urls {
		if strings.HasPrefix(u, "//") {
			u = "https:" + u
		}
		b := p.container(u)
		consented := bytes.Contains(b, []byte(`"requireConsent":true`)) || bytes.Contains(b, []byte(`"requireCookieConsent":true`))
		cookieless := bytes.Contains(b, []byte(`"disableCookies":true`)) && !bytes.Contains(b, []byte(`"disableCookies":false`))
		if !consented && !cookieless {
			return false
		}
	}
	return true
}

// container is a tracker's container script, its first 4 MB; nil when it
// can't be read (then it isn't trusted to wait).
func (p *prober) container(u string) []byte {
	if reserved(u) {
		return nil
	}
	resp, err := p.do(http.MethodGet, u, nil, 0)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return b
}

// sameSite reports whether host is home's, with or without www.
func sameSite(home, host string) bool {
	u, err := url.Parse(home)
	bare := func(h string) string { return strings.TrimPrefix(strings.ToLower(h), "www.") }
	return err == nil && bare(u.Hostname()) == bare(host)
}

func firstAt(re *regexp.Regexp, b []byte) int {
	if loc := re.FindIndex(b); loc != nil {
		return loc[0]
	}
	return -1
}

// earliest of two positions, -1 meaning none.
func earliest(a, b int) int {
	if a < 0 || (b >= 0 && b < a) {
		return b
	}
	return a
}

func firstUnique(all [][]byte, n int) []string {
	var out []string
	for _, m := range all {
		if s := string(m); !slices.Contains(out, s) {
			out = append(out, s)
			if len(out) == n {
				break
			}
		}
	}
	return out
}
