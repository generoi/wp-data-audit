package audit

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Deploys delete these to hide the WordPress version; missing is fine.
var removedOnPurpose = regexp.MustCompile(`File doesn't exist: (readme\.html|license\.txt|wp-config-sample\.php)$`)

// coreFileLine is a core verify-checksums warning about a file.
var coreFileLine = regexp.MustCompile(`File (doesn't verify against checksum|should not exist|doesn't exist): `)

// Kinsta installs its own must-use plugin on every site.
var hostMuPlugins = map[string]bool{"kinsta-mu-plugins": true, "kinsta-mu-plugins.php": true}

// files: PHP under uploads; plugins, mu-plugins and drop-ins the repo
// doesn't deploy; every other PHP file against a composer install of the
// deployed commit, or wordpress.org's checksums when there's none.
func (c *checker) files() {
	f, repo := c.in.Facts.Files, c.in.Repo
	uploads := f.Content + "/uploads/"
	paths := slices.Sorted(maps.Keys(f.Files))
	for _, p := range paths {
		if rest, ok := strings.CutPrefix(p, uploads); ok && !f.Silence[p] {
			v := f.Files[p]
			c.flag(Flag{ID: "upload-php:" + idPart(rest) + ":" + firstN(v, 16), Severity: Urgent, Kind: KindFile,
				Message: "executable file under uploads", Untrusted: rest + " (sha256 " + v + ")"})
		}
	}
	switch {
	case repo == nil:
		c.problem("no repo to compare with: plugins and PHP files not checked")
		return
	case stale(f, repo):
		// What the checkout deploys says nothing about production's commit.
		c.problem("plugins and PHP files not compared: production runs %s, the checkout is at %.12s", firstN(f.Revision, 12), repo.Revision)
		return
	}
	undeployed := c.undeployed(f, repo, paths)
	switch {
	case repo.Local != nil:
		if f.Revision == "" {
			c.info("the deployed commit is unknown (no REVISION file, no deploy run found): PHP files compared with the checkout as it is")
		}
		c.release(f, repo, paths, undeployed)
	case c.in.Facts.Site != nil:
		c.problem("PHP files not compared with the deployed commit: %s", repo.LocalWhy)
		c.checksums(c.in.Facts.Site.Checksums, repo)
	default:
		c.problem("PHP files not verified: %s, and the collector (wordpress.org's checksums) didn't run", repo.LocalWhy)
	}
}

// undeployed flags each plugin, mu-plugin and drop-in on the site that the
// repo doesn't deploy, once as a whole; it returns them ("kind name").
func (c *checker) undeployed(f *FileFacts, repo *Repo, paths []string) map[string]bool {
	units := map[string]bool{}
	for _, p := range paths {
		kind, name := placed(p, f.Content)
		want := map[string]map[string]bool{"plugin": repo.Plugins, "mu-plugin": repo.MuPlugins, "dropin": repo.Dropins}[kind]
		if want == nil || want[name] || (kind == "mu-plugin" && hostMuPlugins[name]) || units[kind+" "+name] {
			continue
		}
		units[kind+" "+name] = true
		c.flag(Flag{ID: kind + ":" + idPart(name), Severity: Urgent, Kind: KindFile,
			Message: kind + " on the site that the repo doesn't deploy", Untrusted: name})
	}
	return units
}

// release compares every PHP file outside uploads with the local install:
// one flag per package or theme, its ID covering every differing file, so
// accepting it holds until any of them changes again.
func (c *checker) release(f *FileFacts, repo *Repo, paths []string, undeployed map[string]bool) {
	content := f.Content
	type diff struct{ changed, extra []string }
	diffs := map[string]*diff{}
	skipped := map[string]int{}
	for _, p := range paths {
		if strings.HasPrefix(p, content+"/uploads/") {
			continue
		}
		kind, name := placed(p, content)
		if undeployed[kind+" "+name] || (kind == "mu-plugin" && hostMuPlugins[name]) {
			continue // flagged as a whole, or the host's
		}
		u := unit(p, content)
		lv, ok := repo.Local[p]
		pure, shaped := f.Shapes[p]
		switch {
		case ok && lv == f.Files[p]:
			continue
		case shaped && pure:
			skipped["built asset manifests (*.asset.php) the hasher found pure data"]++
			continue
		case shaped:
			c.flag(Flag{ID: "asset-shape:" + idPart(p) + ":" + firstN(f.Files[p], 16), Severity: Urgent, Kind: KindRelease,
				Message: "built asset manifest (*.asset.php) that isn't pure data: WordPress runs it, check it for added code", Untrusted: p})
			continue
		case u == content+"/languages":
			skipped["translation files WordPress updates itself (languages)"]++
			continue
		case !ok && (u == content+"/cache" || strings.Contains(p, "/storage/framework/")):
			skipped["caches the site compiles itself (cache/, Acorn's storage/framework/)"]++
			continue
		case !ok && (strings.Contains(p, "/build/") || strings.Contains(p, "/dist/") && strings.HasSuffix(p, ".asset.php")):
			skipped["built files the checkout hasn't built (build/, dist/*.asset.php)"]++
			continue
		}
		d := diffs[u]
		if d == nil {
			d = &diff{}
			diffs[u] = d
		}
		if ok {
			d.changed = append(d.changed, p)
		} else {
			d.extra = append(d.extra, p)
		}
	}
	for _, u := range slices.Sorted(maps.Keys(diffs)) {
		d := diffs[u]
		all := append(slices.Clone(d.changed), d.extra...)
		var sig []string
		for _, p := range all {
			sig = append(sig, p+"="+f.Files[p])
		}
		slices.Sort(sig)
		if len(all) > 5 {
			all = append(all[:5], fmt.Sprintf("and %d more", len(all)-5))
		}
		c.flag(Flag{ID: "release:" + idPart(u) + ":" + short(sig...), Severity: Urgent, Kind: KindRelease,
			Message:   fmt.Sprintf("PHP files differ from the deployed commit: %d changed, %d not in the release", len(d.changed), len(d.extra)),
			Untrusted: u + ": " + strings.Join(all, ", ")})
	}
	for _, what := range slices.Sorted(maps.Keys(skipped)) {
		c.info("%d PHP file(s) not compared: %s", skipped[what], what)
	}
	// The collector runs core, mu-plugins, drop-ins and the site's wp-cli; the
	// hasher doesn't. When those differ, the collector's answers are suspect.
	var ran []string
	for u := range diffs {
		if loadsWithCollector(u, content) {
			ran = append(ran, u)
		}
	}
	for k := range undeployed {
		if strings.HasPrefix(k, "mu-plugin ") || strings.HasPrefix(k, "dropin ") {
			ran = append(ran, k)
		}
	}
	if len(ran) > 0 {
		slices.Sort(ran)
		c.problem("code the collector loads differs from the release (%s): its accounts, options and content findings could be forged; trust the file flags, not those", strings.Join(ran, ", "))
	}
}

// checksums judges wordpress.org's checksums, the fallback when there's no
// local install to compare with.
func (c *checker) checksums(cs Checksums, repo *Repo) {
	if cs.Skipped {
		c.problem("wordpress.org checksums weren't fetched either: core and plugins unverified this time")
		return
	}
	if !repo.PatchedCore {
		for _, l := range cs.Core {
			switch {
			case removedOnPurpose.MatchString(l), strings.Contains(l, "installation doesn't verify against checksums"):
				// deliberate, or the summary line: the file warnings around it are the findings
			case coreFileLine.MatchString(l):
				c.flag(Flag{ID: "core-checksum:" + short(l), Severity: Urgent, Kind: KindChecksum, Message: "WordPress core file fails its checksum", Untrusted: l})
			default: // the check itself failed (no checksums from wordpress.org, say): not a finding
				c.problem("core checksums: %s", l)
			}
		}
	}
	for _, p := range cs.Plugins {
		if repo.PatchedPlugins[p.Plugin] {
			continue
		}
		c.flag(Flag{ID: "plugin-checksum:" + idPart(p.Plugin) + ":" + idPart(p.File), Severity: Urgent, Kind: KindChecksum,
			Message: "plugin file fails its wordpress.org checksum", Untrusted: p.Plugin + "/" + p.File + ": " + p.Message})
	}
	if n := cs.PluginsSkipped; n > 0 {
		c.info("%d plugin(s) have no wordpress.org checksums (premium or custom), so their files weren't verified", n)
	}
}

// stale: the checkout is at another commit than production, so it says
// nothing about which files production's release ships.
func stale(f *FileFacts, repo *Repo) bool {
	return repo != nil && f.Revision != "" && repo.Revision != "" &&
		!strings.HasPrefix(repo.Revision, f.Revision) && !strings.HasPrefix(f.Revision, repo.Revision)
}

// loadsWithCollector reports whether unit u runs when the collector does:
// core, mu-plugins, drop-ins and the site's own wp-cli.
func loadsWithCollector(u, content string) bool {
	switch {
	case u == "core", u == content+"/mu-plugins", strings.HasPrefix(u, content+"/mu-plugins/"), strings.HasPrefix(u, "vendor/wp-cli/"):
		return true
	}
	rest, ok := strings.CutPrefix(u, content+"/")
	return ok && !strings.Contains(rest, "/") && strings.HasSuffix(rest, ".php")
}

// placed says what p is under content: a plugin, mu-plugin or drop-in and
// its name (its folder, or the file for a single-file one); "" for the rest.
func placed(p, content string) (kind, name string) {
	rest, ok := strings.CutPrefix(p, content+"/")
	if !ok {
		return "", ""
	}
	parts := strings.SplitN(rest, "/", 3)
	switch {
	case len(parts) == 1:
		return "dropin", parts[0]
	case parts[0] == "plugins" && parts[1] != "index.php":
		return "plugin", parts[1]
	case parts[0] == "mu-plugins" && parts[1] != "index.php":
		return "mu-plugin", parts[1]
	}
	return "", ""
}

// unit is what a differing file belongs to, one flag per unit: a plugin,
// mu-plugin, theme or vendor package, core, or a content subfolder.
func unit(p, content string) string {
	parts := strings.Split(p, "/")
	if rest, ok := strings.CutPrefix(p, content+"/"); ok {
		sub := strings.Split(rest, "/")
		switch {
		case len(sub) == 1:
			return p
		case (sub[0] == "plugins" || sub[0] == "mu-plugins" || sub[0] == "themes") && len(sub) > 2:
			return content + "/" + sub[0] + "/" + sub[1]
		}
		return content + "/" + sub[0]
	}
	switch {
	case parts[0] == "vendor" && len(parts) > 3:
		return strings.Join(parts[:3], "/")
	case parts[0] == "web" && len(parts) > 1 && parts[1] == "wp", parts[0] == "wp-includes", parts[0] == "wp-admin":
		return "core"
	}
	return parts[0]
}
