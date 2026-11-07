// Package wporg asks wordpress.org's plugin API whether plugins are closed,
// and when each last had a release. Read-only GETs, a few at a time.
package wporg

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	audit "github.com/generoi/wp-data-audit"
)

// Base is the plugin API.
const Base = "https://api.wordpress.org/plugins/info/1.2/"

// Lookup asks about every slug, six at a time. A slug wordpress.org doesn't
// know (a premium plugin under a wordpress.org-like name) is left out.
func Lookup(ctx context.Context, client *http.Client, base string, slugs []string) map[string]audit.WPOrgPlugin {
	out := map[string]audit.WPOrgPlugin{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, slug := range slugs {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			p, known := one(ctx, client, base, slug)
			if known {
				mu.Lock()
				out[slug] = p
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return out
}

// one asks about slug; known is false when wordpress.org has no such plugin.
func one(ctx context.Context, client *http.Client, base, slug string) (p audit.WPOrgPlugin, known bool) {
	q := url.Values{"action": {"plugin_information"}, "request[slug]": {slug}}
	for _, f := range []string{"sections", "versions", "reviews", "screenshots", "banners", "icons", "contributors", "tags", "ratings", "compatibility", "description"} {
		q.Set("request[fields]["+f+"]", "0")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+q.Encode(), nil)
	if err != nil {
		return audit.WPOrgPlugin{Err: err.Error()}, true
	}
	req.Header.Set("User-Agent", "wp-data-audit")
	resp, err := client.Do(req)
	if err != nil {
		return audit.WPOrgPlugin{Err: err.Error()}, true
	}
	defer resp.Body.Close()
	var r struct {
		Error       string `json:"error"`
		Closed      bool   `json:"closed"`
		ClosedDate  string `json:"closed_date"`
		Reason      string `json:"reason_text"`
		LastUpdated string `json:"last_updated"` // "2026-08-18 11:42pm GMT"
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return audit.WPOrgPlugin{Err: "wordpress.org: " + err.Error()}, true
	}
	switch {
	case r.Closed:
		return audit.WPOrgPlugin{Closed: true, Reason: r.Reason, ClosedDate: r.ClosedDate}, true
	case resp.StatusCode == http.StatusNotFound:
		return audit.WPOrgPlugin{}, false
	case resp.StatusCode != http.StatusOK || r.Error != "":
		return audit.WPOrgPlugin{Err: errors.Join(errors.New(resp.Status), errors.New(r.Error)).Error()}, true
	}
	day, _, _ := strings.Cut(r.LastUpdated, " ")
	if _, err := time.Parse("2006-01-02", day); err != nil {
		return audit.WPOrgPlugin{Err: "wordpress.org: last_updated " + r.LastUpdated}, true
	}
	return audit.WPOrgPlugin{LastUpdated: day}, true
}
