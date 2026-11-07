package audit

import (
	"fmt"
	"strings"
	"time"
)

// RetentionAfter is how old kept personal data may get before a site without
// a retention setting is flagged.
const RetentionAfter = 2 * 365 * 24 * time.Hour

// Retention is how long personal data is kept: counts, dates and settings.
type Retention struct {
	Forms []FormRetention `json:"forms"`
	Woo   []WooRetention  `json:"woo"`
}

// FormRetention is one Gravity Forms form: Policy is its Personal Data
// setting (retain, trash, delete), Days how long before trash or delete.
type FormRetention struct {
	Blog    int    `json:"blog"`
	FormID  int    `json:"form_id"`
	Title   string `json:"title"`
	Entries int    `json:"entries"`
	Oldest  string `json:"oldest"`
	Policy  string `json:"policy"`
	Days    int    `json:"days"`
}

// WooRetention is one shop: Settings are WooCommerce's Accounts & Privacy
// retention options ("6 months", "" when off).
type WooRetention struct {
	Blog     int               `json:"blog"`
	Orders   int               `json:"orders"`
	Oldest   string            `json:"oldest"`
	Settings map[string]string `json:"settings"`
}

func (c *checker) retention(cur *Snapshot) {
	now := cur.GeneratedAt
	if now.IsZero() {
		now = time.Now()
	}
	old := func(s string) (time.Time, bool) {
		t, err := time.Parse("2006-01-02 15:04:05", s)
		return t, err == nil && now.Sub(t) > RetentionAfter
	}
	// One flag per site, its ID covering the forms, so accepting holds until
	// another form starts keeping old entries.
	type site struct {
		ids, list []string
		entries   int
		oldest    time.Time
	}
	sites := map[int]*site{}
	var blogs []int
	for _, f := range cur.Retention.Forms {
		t, isOld := old(f.Oldest)
		if f.Entries == 0 || !isOld || (f.Policy != "retain" && f.Days > 0) {
			continue
		}
		s := sites[f.Blog]
		if s == nil {
			s = &site{oldest: t}
			sites[f.Blog] = s
			blogs = append(blogs, f.Blog)
		}
		s.ids = append(s.ids, fmt.Sprint(f.FormID))
		s.list = append(s.list, fmt.Sprintf("form %d %q: %d entries since %s", f.FormID, f.Title, f.Entries, t.Format("2006-01-02")))
		s.entries += f.Entries
		if t.Before(s.oldest) {
			s.oldest = t
		}
	}
	for _, b := range blogs {
		s := sites[b]
		c.flag(Flag{ID: fmt.Sprintf("retention:forms:%d:%s", b, short(s.ids...)), Severity: Review, Kind: "retention",
			Message: fmt.Sprintf("%d forms keep every entry (%d in all, the oldest from %s): set a retention period (form settings → Personal Data) or delete old entries",
				len(s.ids), s.entries, s.oldest.Format("2006-01-02")),
			Untrusted: fmt.Sprintf("blog %d: %s", b, strings.Join(s.list, "; "))})
	}
	for _, w := range cur.Retention.Woo {
		t, isOld := old(w.Oldest)
		if w.Orders == 0 || !isOld || w.Settings["anonymize_completed_orders"] != "" {
			continue
		}
		var off []string
		for _, k := range []string{"anonymize_completed_orders", "delete_inactive_accounts"} {
			if w.Settings[k] == "" {
				off = append(off, strings.ReplaceAll(k, "_", " "))
			}
		}
		c.flag(Flag{ID: fmt.Sprintf("retention:woo:%d", w.Blog), Severity: Review, Kind: "retention",
			Message: fmt.Sprintf("orders keep customers' personal data indefinitely: %d orders, the oldest from %s, and %s are off (WooCommerce → Settings → Accounts & Privacy); anonymising keeps the order for the 6-year bookkeeping period, without the person",
				w.Orders, t.Format("2006-01-02"), strings.Join(off, " and ")),
			Untrusted: fmt.Sprintf("blog %d", w.Blog)})
	}
}
