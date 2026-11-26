package web

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const (
	gtmLoader  = `<script>(function(w,d,s,l,i){j.src='https://www.googletagmanager.com/gtm.js?id='+i;})(window,document,'script','dataLayer','GTM-ABC1234');</script>`
	cmp        = `<script id="genero-cmp/js-js" src="/app/plugins/genero-cmp/dist/main.js"></script>`
	modeGtag   = `<script>gtag('consent', 'default', {ad_storage:'denied'});</script>`
	modePush   = `<script>window.dataLayer.push(["consent","default",{"ad_storage":"denied"}]);</script>`
	hotjar     = `<script>h._hjSettings={hjid:1};a.src='https://static.hotjar.com/c/hotjar-1.js';</script>`
	clarity    = `<script>t.src="https://www.clarity.ms/tag/"+i;</script>`
	matomoSnip = `<script src="https://cdn.matomo.cloud/site.matomo.cloud/container_AbC123.js"></script>`
)

func TestEarlyTrackers(t *testing.T) {
	for _, tc := range []struct {
		name, page string
		want       []string
	}{
		{"consent tool first", cmp + gtmLoader + hotjar, nil},
		{"GTM before the consent default", gtmLoader + modeGtag, []string{"gtm"}},
		{"consent default first", modePush + gtmLoader, nil},
		{"consent mode doesn't hold back non-Google trackers", modeGtag + gtmLoader + clarity, []string{"clarity"}},
		{"tracker before the consent tool", hotjar + cmp + gtmLoader, []string{"hotjar"}},
		{"no consent at all", gtmLoader + matomoSnip, []string{"gtm", "matomo"}},
		{"parked by the consent tool", `<script type="text/plain" data-category="statistics">` + hotjar[8:] + cmp, nil},
		{"noscript fallback only", `<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-ABC1234"></iframe><script src="https://www.googletagmanager.com/gtm.js"></script></noscript>`, nil},
		{"escaped inside a consent tool's JSON", `<script>var cfg={"head":"https:\/\/www.googletagmanager.com\/gtm.js?id=GTM-ABC1234"};</script>`, nil},
		{"a dns-prefetch hint loads nothing", `<link rel='dns-prefetch' href='//static.hotjar.com' />` + cmp, nil},
		{"Matomo told to wait", `<script>_paq.push(['requireConsent']);</script>` + matomoSnip, nil},
	} {
		if got := earlyTrackers([]byte(tc.page)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Containers are read from where a browser reads them: a GTM container that
// loads a consent tool, or a cookieless Matomo container, doesn't count.
func TestProbeTrackersContainers(t *testing.T) {
	pages := map[string]string{
		"https://www.global.fi/":      strings.ReplaceAll(gtmLoader, "GTM-ABC1234", "GTM-BARE123"),
		"https://gtm-cookiebot.fi/":   gtmLoader,
		"https://gtm-bare.fi/":        strings.ReplaceAll(gtmLoader, "GTM-ABC1234", "GTM-BARE123"),
		"https://matomo-nocookie.fi/": matomoSnip,
		"https://matomo-cookies.fi/":  strings.ReplaceAll(matomoSnip, "AbC123", "Cook1e"),
	}
	containers := map[string]string{
		"https://www.googletagmanager.com/gtm.js?id=GTM-ABC1234":         `[3,"v",[0,"https://consent.cookiebot.",[15,"r"]],"/uc.js?cbid="]`,
		"https://www.googletagmanager.com/gtm.js?id=GTM-BARE123":         `{"macros":[]}`,
		"https://cdn.matomo.cloud/site.matomo.cloud/container_AbC123.js": `{"disableCookies":true,"requireConsent":false}`,
		"https://cdn.matomo.cloud/site.matomo.cloud/container_Cook1e.js": `{"disableCookies":true},{"disableCookies":false}`,
	}
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == "https://network-root.fi/" { // a network's root sends visitors to another install
			return &http.Response{StatusCode: http.StatusMovedPermanently, Body: http.NoBody, Header: http.Header{"Location": {"https://www.global.fi/"}}, Request: r}, nil
		}
		body, ok := pages[r.URL.String()]
		if !ok {
			body, ok = containers[r.URL.String()]
		}
		status := http.StatusOK
		if !ok {
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
	})}
	for home, want := range map[string][]string{
		"https://gtm-cookiebot.fi":   nil,
		"https://gtm-bare.fi":        {"gtm"},
		"https://matomo-nocookie.fi": nil,
		"https://matomo-cookies.fi":  {"matomo"},
		"https://network-root.fi":    nil,
	} {
		w := Probe(context.Background(), client, Target{Home: home, Options: map[string]string{"home": home}}, Options{Public: true})
		if len(w.Sites) != 1 || !slices.Equal(w.Sites[0].Trackers, want) {
			t.Errorf("%s: %+v, want %v", home, w.Sites, want)
		}
	}
}
