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
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed collector.php
var collector string

// Hasher is the shell script to pipe to `sh -s` over SSH in the release:
// its PHP files and their hashes from the system's find and sha256sum, so
// nothing in the release runs (ParseRelease reads its output).
//
//go:embed hasher.sh
var Hasher string

// HasherCommand is the remote command to pipe Hasher to, after a `cd` into
// the release: an empty environment and the system's PATH, so a tool the
// site user put in ~/bin or exported doesn't stand in for find or sha256sum.
// (Their shell startup files still run before it over SSH: a determined
// attacker with the site user's home can still interfere.)
const HasherCommand = "exec /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh -s"

// WPArgs are the wp-cli flags to run Script with: plugins and themes stay
// unloaded, so they can't interfere with what it reports.
var WPArgs = []string{"eval-file", "-", "--skip-plugins", "--skip-themes"}

var (
	roleRE = regexp.MustCompile(`^[a-z0-9_-]+$`)
	siteRE = regexp.MustCompile(`^[a-z0-9.-]+$`)
)

// Script is the PHP to pipe to `wp eval-file -` on the site. publicRoles
// are the roles anyone can get, by site host (or blog id on a multisite):
// their users are only counted. `customer` is public wherever WooCommerce
// runs; every other role is listed, so a subscriber on a site without
// sign-ups gets flagged.
func Script(publicRoles map[string][]string) (string, error) {
	var b strings.Builder
	b.WriteString("<?php\n$wpda_public_roles = [")
	for _, site := range slices.Sorted(maps.Keys(publicRoles)) {
		if !siteRE.MatchString(site) {
			return "", fmt.Errorf("public roles: site %q: want a host or blog id", site)
		}
		fmt.Fprintf(&b, "'%s' => [", site)
		for _, r := range publicRoles[site] {
			if !roleRE.MatchString(r) {
				return "", fmt.Errorf("public roles: role %q: want lowercase letters, digits, _ and -", r)
			}
			fmt.Fprintf(&b, "'%s', ", r)
		}
		b.WriteString("], ")
	}
	b.WriteString("];\n")
	body, ok := strings.CutPrefix(collector, "<?php")
	if !ok {
		return "", errors.New("collector.php doesn't start with <?php")
	}
	return b.String() + body, nil
}

// Parse reads the snapshot from the collector's output, ignoring anything
// printed around it.
func Parse(out []byte) (*Snapshot, error) {
	var snap Snapshot
	if err := block(out, "collector", &snap, &snap.Version); err != nil {
		return nil, err
	}
	return &snap, nil
}

// ParseRelease reads the hasher's output: keyword lines, then sha256sum's
// under FILES and SILENCE.
func ParseRelease(out []byte) (*Release, error) {
	_, rest, ok := strings.Cut(string(out), "\nWPDA-BEGIN\n")
	if !ok {
		return nil, errors.New("no WPDA-BEGIN in the hasher's output")
	}
	body, _, ok := strings.Cut(rest, "\nWPDA-END")
	if !ok {
		return nil, errors.New("no WPDA-END in the hasher's output (cut short?)")
	}
	r := &Release{Files: map[string]string{}, Silence: map[string]bool{}}
	section := ""
	for _, line := range strings.Split(body, "\n") {
		key, val, _ := strings.Cut(line, " ")
		switch key {
		case "VERSION":
			r.Version, _ = strconv.Atoi(val)
			continue
		case "ERROR":
			r.Errors = append(r.Errors, val)
			continue
		case "REVISION":
			r.Revision = val
			continue
		case "CONTENT":
			r.Content = val
			continue
		case "FILES", "SILENCE":
			section = key
			continue
		case "":
			continue
		}
		sum, path, err := sumLine(line)
		switch {
		case err != nil:
			r.Errors = append(r.Errors, err.Error())
		case section == "FILES":
			r.Files[path] = sum
		case section == "SILENCE":
			r.Silence[path] = true
		}
	}
	if r.Version != 1 {
		return nil, fmt.Errorf("hasher output version %d, want 1", r.Version)
	}
	return r, nil
}

var sumRE = regexp.MustCompile(`^\\?([0-9a-f]{64})  (.+)$`)

// sumLine is one sha256sum line. A name with a backslash or newline is
// escaped, and its line starts with a backslash.
func sumLine(line string) (sum, path string, err error) {
	m := sumRE.FindStringSubmatch(line)
	if m == nil {
		return "", "", fmt.Errorf("hasher: unexpected line %q", firstN(line, 80))
	}
	path = m[2]
	if strings.HasPrefix(line, `\`) {
		path = strings.NewReplacer(`\\`, `\`, `\n`, "\n", `\r`, "\r").Replace(path)
	}
	return m[1], strings.ReplaceAll(path, "//", "/"), nil
}

func block(out []byte, what string, v any, version *int) error {
	_, rest, ok := strings.Cut(string(out), "\nWPDA-BEGIN\n")
	if !ok {
		return fmt.Errorf("no WPDA-BEGIN in the %s's output", what)
	}
	body, _, ok := strings.Cut(rest, "\nWPDA-END")
	if !ok {
		return fmt.Errorf("no WPDA-END in the %s's output (cut short?)", what)
	}
	if err := json.Unmarshal([]byte(body), v); err != nil {
		return fmt.Errorf("%s output: %w", what, err)
	}
	if *version != 1 {
		return fmt.Errorf("%s output version %d, want 1", what, *version)
	}
	return nil
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
	PublicRoleCaps   map[string][]string `json:"public_role_caps"` // what each public role (blog-tagged) grants
	Users            []User            `json:"users"`
	WooKeys          []WooKey          `json:"woo_keys"`
	Content          []Match           `json:"content"`
	ContentTruncated bool              `json:"content_truncated"`
	Checksums        Checksums         `json:"checksums"`
	Errors           []string          `json:"errors"`
	// Release is the hasher's file list, joined in by the caller (runner);
	// nil when it didn't run.
	Release *Release `json:"release,omitempty"`
	// NoCollector: the collector didn't run (the site's wp-cli failed), so
	// only the hasher's files are judged. Such a snapshot isn't saved.
	NoCollector bool `json:"-"`
}

// Release is the hasher's output: every PHP file of the release and under
// uploads, path (from the root) → sha256; Silence are the uploads files that
// are empty or a "Silence is golden" guard.
type Release struct {
	Version  int               `json:"version"`
	Revision string            `json:"revision"` // the deployed commit: REVISION, else the caller's
	Content  string            `json:"content"`  // web/app (Bedrock) or wp-content
	Files    map[string]string `json:"files"`
	Silence  map[string]bool   `json:"silence,omitempty"`
	Errors   []string          `json:"errors"`
}

type Registration struct {
	Open      bool     `json:"users_can_register"`
	Role      string   `json:"default_role"`
	RoleCaps  []string `json:"default_role_caps"`
}

// User is a user holding a role outside the site's public roles, a
// capability outside their roles, or an application password. On a multisite,
// roles and capabilities from sites other than the main one are prefixed
// "<blog id>:"; network admins have the role super_admin. Privileged is set
// when any role isn't public.
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
	Blog         int    `json:"blog"`
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
	Blog  int    `json:"blog"`
	Table string `json:"table"`
	ID    int64  `json:"id"`
	Field string `json:"field"`
	Key   string `json:"key"`
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
