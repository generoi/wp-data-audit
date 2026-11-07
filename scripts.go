package audit

import (
	_ "embed"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

//go:embed collector.php
var collector string

// Hasher is the shell script to pipe to HasherCommand in the release: its
// PHP files and their hashes, and risky data files by name, from the
// server's own find and sha256sum, so nothing in the release runs
// (ParseFiles reads its output).
//
//go:embed hasher.sh
var Hasher string

// HasherCommand is the remote command to pipe Hasher to, after a `cd` into
// the release: an empty environment and the system's PATH, so a tool the
// site user put in ~/bin or exported doesn't stand in for find or sha256sum.
// (Their shell startup files still run before it over SSH: a determined
// attacker with the site user's home can still interfere.)
const HasherCommand = "exec /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh -s"

// WPArgs are the wp-cli arguments to pipe the collector script to: plugins
// and themes stay unloaded, so they can't interfere with what it reports.
var WPArgs = []string{"eval-file", "-", "--skip-plugins", "--skip-themes"}

// Section is a slow part of the collector that can be left out.
type Section string

const (
	SectionContent   Section = "content"
	SectionRetention Section = "retention"
	SectionChecksums Section = "checksums" // wordpress.org's, one download per plugin
)

var (
	roleRE = regexp.MustCompile(`^[a-z0-9_-]+$`)
	siteRE = regexp.MustCompile(`^[a-z0-9.-]+$`)
)

// Script is the collector: PHP to pipe to `wp` with WPArgs. publicRoles are
// the roles anyone can get, by site host (or blog id on a multisite): their
// users are only counted. `customer` is public wherever WooCommerce runs;
// every other role is listed, so a subscriber on a site without sign-ups is
// flagged. skip are sections not to run.
func Script(publicRoles map[string][]string, skip ...Section) (string, error) {
	var b strings.Builder
	b.WriteString("<?php\n$wpda_skip = [")
	for _, s := range skip {
		if s != SectionContent && s != SectionRetention && s != SectionChecksums {
			return "", fmt.Errorf("collector section %q: want content, retention or checksums", s)
		}
		fmt.Fprintf(&b, "'%s' => true, ", s)
	}
	b.WriteString("];\n$wpda_public_roles = [")
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
