package audit

import (
	"slices"
	"time"
)

// Baseline is what the next audit compares with: only the facts a change in
// is a finding (who holds which roles and credentials, the watched options)
// and what can't be seen again (when an account was last used). Kept small:
// the rest of a run's facts aren't saved.
type Baseline struct {
	At      time.Time         `json:"at"`
	Home    string            `json:"home"`
	Options map[string]string `json:"options"`
	Users   []BaselineUser    `json:"users"`
	WooKeys []WooKeyRef       `json:"woo_keys"`
	// Sensitive options' value hashes, active plugins and cron hooks, per
	// site. Nil in a baseline from before they were collected: then nothing
	// is "new" against it.
	Sensitive map[string]string   `json:"sensitive"` // not omitempty: an empty one is a baseline, nil isn't
	Plugins   map[string][]string `json:"plugins"`
	Cron      map[string][]string `json:"cron"`
}

// BaselineUser is a listed account. LastSeen is the newest sign of its use
// any audit saw: a session's login, last-activity meta, an application
// password's use; a login seen once is remembered.
type BaselineUser struct {
	ID           int      `json:"id"`
	Roles        []string `json:"roles"`
	Privileged   bool     `json:"privileged"`
	AppPasswords []string `json:"app_passwords"`
	LastSeen     int64    `json:"last_seen,omitempty"`
}

type WooKeyRef struct {
	Blog int `json:"blog"`
	ID   int `json:"id"`
}

// user is prev's account id; ok false when prev is nil or hasn't it.
func (b *Baseline) user(id int) (BaselineUser, bool) {
	if b == nil {
		return BaselineUser{}, false
	}
	i := slices.IndexFunc(b.Users, func(u BaselineUser) bool { return u.ID == id })
	if i < 0 {
		return BaselineUser{}, false
	}
	return b.Users[i], true
}

func (b *Baseline) hasAppPassword(uuid string) bool {
	return b != nil && slices.ContainsFunc(b.Users, func(u BaselineUser) bool { return slices.Contains(u.AppPasswords, uuid) })
}

func (b *Baseline) hasWooKey(k WooKey) bool {
	return b != nil && slices.Contains(b.WooKeys, WooKeyRef{k.Blog, k.ID})
}

// lastSeen is each listed account's newest sign of use: what s shows, or
// what prev remembered.
func lastSeen(prev *Baseline, s *SiteFacts) map[int]int64 {
	// A WooCommerce REST key's last access (a MySQL datetime, the site's
	// time: a few hours either way doesn't matter here) is its user's use.
	keys := map[int]int64{}
	for _, k := range s.WooKeys {
		if t, err := time.Parse(time.DateTime, k.LastAccess); err == nil {
			keys[k.UserID] = max(keys[k.UserID], t.Unix())
		}
	}
	out := map[int]int64{}
	for _, u := range s.Users {
		seen := max(u.LastActive, keys[u.ID])
		if p, ok := prev.user(u.ID); ok {
			seen = max(seen, p.LastSeen)
		}
		for _, x := range u.Sessions {
			seen = max(seen, x.Login)
		}
		for _, p := range u.AppPasswords {
			seen = max(seen, p.LastUsed)
		}
		out[u.ID] = seen
	}
	return out
}

func newBaseline(at time.Time, s *SiteFacts, seen map[int]int64) *Baseline {
	b := &Baseline{At: at, Home: s.Home, Options: s.Options, Sensitive: s.Sensitive, Plugins: s.ActivePlugins, Cron: s.Cron}
	for _, u := range s.Users {
		bu := BaselineUser{ID: u.ID, Roles: slices.Sorted(slices.Values(u.Roles)), Privileged: u.Privileged, LastSeen: seen[u.ID]}
		for _, p := range u.AppPasswords {
			bu.AppPasswords = append(bu.AppPasswords, p.UUID)
		}
		b.Users = append(b.Users, bu)
	}
	for _, k := range s.WooKeys {
		b.WooKeys = append(b.WooKeys, WooKeyRef{k.Blog, k.ID})
	}
	return b
}
