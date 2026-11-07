// Package audit is a light, read-only security audit of a WordPress site: who
// holds privileged accounts and credentials and where they log in from, PHP
// files that differ from the deployed release, files anyone can download
// that shouldn't be public, what the public site gives away, personal data
// kept with no end, and scripts or iframes in content.
//
// Three sources observe a site (Facts): a PHP collector run through the
// site's wp-cli (Script), a shell hasher run with the server's own tools
// (Hasher), and HTTP probes from outside (package web). Check judges them
// against the last run's Baseline, the site's repo (ReadRepo) and a Policy,
// and returns a Report and the next Baseline. Nothing here touches the
// network or calls a model: a clean site costs no tokens.
package audit
