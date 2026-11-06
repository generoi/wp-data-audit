// Package audit is a light security audit of a WordPress site's data: who
// holds privileged accounts and credentials, where they log in from, PHP
// files where none belong, failed checksums, and scripts or iframes in
// content. A PHP collector (Script) runs on the site and prints facts; Check
// compares them with the previous snapshot and the site's accepted flags.
// Nothing in here calls a model: a clean site costs no tokens.
package audit

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

//go:embed collector.php
var collector string

// DefaultLowRoles are the roles only counted, never listed.
var DefaultLowRoles = []string{"subscriber", "customer"}

var roleRE = regexp.MustCompile(`^[a-z0-9_-]+$`)

// Script is the PHP to pipe to `wp eval-file -` on the site. lowRoles are
// added to DefaultLowRoles: roles whose users are only counted, such as a
// membership site's member role.
func Script(lowRoles []string) (string, error) {
	roles := append([]string{}, DefaultLowRoles...)
	for _, r := range lowRoles {
		if !roleRE.MatchString(r) {
			return "", fmt.Errorf("role %q: want lowercase letters, digits, _ and -", r)
		}
		roles = append(roles, r)
	}
	body, ok := strings.CutPrefix(collector, "<?php")
	if !ok {
		return "", errors.New("collector.php doesn't start with <?php")
	}
	return "<?php\n$wpda_low_roles = ['" + strings.Join(roles, "', '") + "'];\n" + body, nil
}

// Parse reads the snapshot from the collector's output, ignoring anything
// plugins printed around it.
func Parse(out []byte) (*Snapshot, error) {
	s := string(out)
	_, rest, ok := strings.Cut(s, "\nWPDA-BEGIN\n")
	if !ok {
		return nil, errors.New("no WPDA-BEGIN in the collector's output")
	}
	body, _, ok := strings.Cut(rest, "\nWPDA-END")
	if !ok {
		return nil, errors.New("no WPDA-END in the collector's output (cut short?)")
	}
	var snap Snapshot
	if err := json.Unmarshal([]byte(body), &snap); err != nil {
		return nil, fmt.Errorf("collector output: %w", err)
	}
	if snap.Version != 1 {
		return nil, fmt.Errorf("collector output version %d, want 1", snap.Version)
	}
	return &snap, nil
}

// Snapshot is what the collector printed.
type Snapshot struct {
	Version          int               `json:"version"`
	GeneratedAt      time.Time         `json:"generated_at"`
	Home             string            `json:"home"`
	WPVersion        string            `json:"wp_version"`
	WooCommerce      bool              `json:"woocommerce"`
	Multisite        bool              `json:"multisite"`
	Options          map[string]string `json:"options"`
	Registration     Registration      `json:"registration"`
	RoleCounts       map[string]int    `json:"role_counts"`
	Users            []User            `json:"users"`
	WooKeys          []WooKey          `json:"woo_keys"`
	Content          []Match           `json:"content"`
	ContentTruncated bool              `json:"content_truncated"`
	Files            Files             `json:"files"`
	Checksums        Checksums         `json:"checksums"`
	Errors           []string          `json:"errors"`
}

type Registration struct {
	Open      bool     `json:"users_can_register"`
	Role      string   `json:"default_role"`
	RoleCaps  []string `json:"default_role_caps"`
}

// User is a user holding a role outside the low roles, a capability outside
// their roles, or an application password.
type User struct {
	ID           int           `json:"id"`
	Login        string        `json:"login"`
	Email        string        `json:"email"`
	Registered   string        `json:"registered"`
	Roles        []string      `json:"roles"`
	Privileged   bool          `json:"privileged"`
	ExtraCaps    []string      `json:"extra_caps"`
	Sessions     []Session     `json:"sessions"`
	AppPasswords []AppPassword `json:"app_passwords"`
}

type Session struct {
	IP         string `json:"ip"`
	UA         string `json:"ua"`
	Login      int64  `json:"login"`
	Expiration int64  `json:"expiration"`
}

type AppPassword struct {
	UUID     string `json:"uuid"`
	Name     string `json:"name"`
	Created  int64  `json:"created"`
	LastUsed int64  `json:"last_used"`
	LastIP   string `json:"last_ip"`
}

type WooKey struct {
	ID           int    `json:"key_id"`
	UserID       int    `json:"user_id"`
	Description  string `json:"description"`
	Permissions  string `json:"permissions"`
	TruncatedKey string `json:"truncated_key"`
	LastAccess   string `json:"last_access"`
}

// Match is one suspicious value found in content: Hash identifies kind and
// value, so the same script or iframe host is one flag wherever it appears.
// Count is how often it appears, At the first few places.
type Match struct {
	Kind    string     `json:"kind"`
	Hash    string     `json:"hash"`
	Snippet string     `json:"snippet"`
	Encoded bool       `json:"encoded"`
	Count   int        `json:"count"`
	At      []Location `json:"at"`
}

type Location struct {
	Table string `json:"table"`
	ID    int64  `json:"id"`
	Field string `json:"field"`
	Key   string `json:"key"`
}

type Files struct {
	UploadsPHP       []File   `json:"uploads_php"`
	UploadsTruncated bool     `json:"uploads_truncated"`
	Plugins          []string `json:"plugins"`
	MuPlugins        []string `json:"mu_plugins"`
	Dropins          []string `json:"dropins"`
}

type File struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Mtime   int64  `json:"mtime"`
	SHA256  string `json:"sha256"`
	Silence bool   `json:"silence"`
}

type Checksums struct {
	Core           []string         `json:"core"`
	Plugins        []PluginChecksum `json:"plugins"`
	PluginsSkipped int              `json:"plugins_skipped"`
}

type PluginChecksum struct {
	Plugin  string `json:"plugin"`
	File    string `json:"file"`
	Message string `json:"message"`
}
