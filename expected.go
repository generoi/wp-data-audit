package audit

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ContentDir is where a Bedrock repo keeps plugins, mu-plugins and drop-ins.
const ContentDir = "web/app"

// SettingsFile is the repo's own audit settings, at its root:
//
//	{
//	    "public_roles": {"members.example": ["subscriber"]},
//	    "client_domains": ["client.example"]
//	}
//
// public_roles keys are a site's host or, on a multisite, its blog id. A file
// of its own, not composer.json: Composer's lock hash covers `extra`.
const SettingsFile = "data-audit.json"

// ReadRepo reads a Bedrock checkout: what it deploys (Composer packages by
// their installer path, plus what git tracks under web/app) and its
// SettingsFile. The checkout should be at the deployed commit: a branch that
// adds or drops a plugin shows up as a flag.
func ReadRepo(dir string) (*Repo, error) {
	exp := &Repo{Plugins: map[string]bool{}, MuPlugins: map[string]bool{}, Dropins: map[string]bool{}, PatchedPlugins: map[string]bool{}}

	var cj struct {
		Extra struct {
			InstallerPaths map[string][]string        `json:"installer-paths"`
			DropinPaths    map[string][]string        `json:"dropin-paths"`
			Patches        map[string]json.RawMessage `json:"patches"`
			PatchesFile    string                     `json:"patches-file"`
		} `json:"extra"`
	}
	if err := readJSON(filepath.Join(dir, "composer.json"), &cj); err != nil {
		return nil, err
	}
	var settings struct {
		PublicRoles   map[string][]string `json:"public_roles"`
		ClientDomains []string            `json:"client_domains"`
	}
	if err := readJSON(filepath.Join(dir, SettingsFile), &settings); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	exp.PublicRoles = settings.PublicRoles
	exp.ClientDomains = settings.ClientDomains
	var lock struct {
		Packages    []lockPackage `json:"packages"`
		PackagesDev []lockPackage `json:"packages-dev"`
	}
	if err := readJSON(filepath.Join(dir, "composer.lock"), &lock); err != nil {
		return nil, err
	}

	where := map[string]map[string]bool{"plugins": exp.Plugins, "mu-plugins": exp.MuPlugins}
	types := map[string]string{}
	for _, p := range lock.Packages { // packages-dev aren't installed on production
		types[p.Name] = p.Type
		if set := where[installDir(p, cj.Extra.InstallerPaths)]; set != nil {
			set[cmp.Or(p.Extra.InstallerName, base(p.Name))] = true
		}
	}

	// koodimonni/composer-dropin-installer copies single files from a package:
	// "web/app/mu-plugins": ["package:vendor/name:path/file.php"].
	for dir, rules := range cj.Extra.DropinPaths {
		sub := contentSub(strings.TrimSuffix(dir, "/") + "/")
		set := where[sub]
		if strings.TrimSuffix(dir, "/") == ContentDir {
			set = exp.Dropins
		}
		for _, r := range rules {
			if rest, ok := strings.CutPrefix(r, "package:"); ok && set != nil {
				if _, file, ok := strings.Cut(rest, ":"); ok {
					set[filepath.Base(file)] = true
				}
			}
		}
	}

	patched := map[string]bool{}
	for name := range cj.Extra.Patches {
		patched[name] = true
	}
	for _, f := range []string{cj.Extra.PatchesFile, "patches.json"} {
		if f == "" {
			continue
		}
		var pj struct {
			Patches map[string]json.RawMessage `json:"patches"`
		}
		if err := readJSON(filepath.Join(dir, f), &pj); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for name := range pj.Patches {
			patched[name] = true
		}
	}
	for name := range patched {
		switch {
		case strings.HasPrefix(name, "roots/wordpress"), name == "johnpbloch/wordpress-core":
			exp.PatchedCore = true
		case types[name] == "wordpress-plugin":
			exp.PatchedPlugins[base(name)] = true
		}
	}

	if rev, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output(); err == nil {
		exp.Revision = strings.TrimSpace(string(rev))
	}
	if _, err := os.Stat(filepath.Join(dir, "vendor", "composer", "installed.json")); err != nil {
		exp.LocalWhy = "the checkout has no composer install"
	} else if exp.Local, err = hashTree(dir); err != nil {
		exp.Local, exp.LocalWhy = nil, "hashing the checkout: "+err.Error()
	}

	out, err := exec.Command("git", "-C", dir, "ls-files", "-z", "--", ContentDir).Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	for _, p := range strings.Split(string(out), "\x00") {
		rest, ok := strings.CutPrefix(p, ContentDir+"/")
		if !ok {
			continue
		}
		parts := strings.SplitN(rest, "/", 3)
		switch {
		case len(parts) == 1 && strings.HasSuffix(parts[0], ".php"):
			exp.Dropins[parts[0]] = true
		case len(parts) >= 2 && where[parts[0]] != nil:
			where[parts[0]][parts[1]] = true
		}
	}
	return exp, nil
}

// SameFiles reports whether the checkout at dir would install the same PHP
// files as commit rev: nothing between them touched Composer's files, the
// patches or web/. Then a production a few commits behind (README or
// workflow changes since its deploy) is still compared.
func SameFiles(dir, rev string) bool {
	if rev == "" {
		return false
	}
	cmd := exec.Command("git", "-C", dir, "diff", "--quiet", rev, "HEAD", "--",
		"composer.json", "composer.lock", "patches.json", "patches", "web")
	return cmd.Run() == nil // exit 1: changes; other errors (rev not fetched): unknown
}

// phpFile is what the hasher hashes: the same rule on both sides.
var phpFile = regexp.MustCompile(`(?i)\.(php\d?|phtml|phar|pht|phps|inc)$`)

// hashTree hashes a composer install's PHP files the way hasher.php does on
// the server: core, vendor and the content dir, not uploads or Composer's
// generated autoloaders, symlinked folders not followed.
func hashTree(dir string) (map[string]string, error) {
	files := map[string]string{}
	for _, root := range []string{ContentDir, "vendor", "web/wp"} {
		err := filepath.WalkDir(filepath.Join(dir, root), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			rel = filepath.ToSlash(rel)
			if d.IsDir() && (rel == ContentDir+"/uploads" || rel == "vendor/composer") {
				return filepath.SkipDir
			}
			if !d.Type().IsRegular() || !phpFile.MatchString(d.Name()) {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			files[rel] = fmt.Sprintf("%x:%d", sum[:8], len(b))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

type lockPackage struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Extra struct {
		InstallerName string `json:"installer-name"` // composer/installers' folder-name override
	} `json:"extra"`
}

// installDir is "plugins" or "mu-plugins" for a package that installs there.
// A path naming the package wins over one matching its type, as composer
// projects list single packages to move them out of their type's folder.
func installDir(p lockPackage, paths map[string][]string) string {
	byType := ""
	for path, rules := range paths {
		for _, r := range rules {
			if r == p.Name {
				return contentSub(path)
			}
			if r == "type:"+p.Type && byType == "" {
				byType = contentSub(path)
			}
		}
	}
	return byType
}

func contentSub(path string) string {
	rest, ok := strings.CutPrefix(path, ContentDir+"/")
	if !ok {
		return ""
	}
	sub, _, _ := strings.Cut(rest, "/")
	return sub
}

func base(name string) string {
	_, b, _ := strings.Cut(name, "/")
	return b
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
