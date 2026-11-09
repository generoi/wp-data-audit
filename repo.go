package audit

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
)

// ContentDir is where a Bedrock repo keeps plugins, mu-plugins and drop-ins.
const ContentDir = "web/app"

// SettingsFile is the repo's own audit settings, at its root:
//
//	{
//	    "public_roles": {"members.example": ["subscriber"]},
//	    "client_domains": ["client.example"],
//	    "public_uploads": ["models/product-3d"]
//	}
//
// public_roles keys are a site's host or, on a multisite, its blog id.
// public_uploads are folders under uploads served on purpose. A file
// of its own, not composer.json: Composer's lock hash covers `extra`.
const SettingsFile = "data-audit.json"

// Repo is what the site's repo says: what it deploys (plugin, mu-plugin and
// drop-in names, and what carries a patch, whose checksums are expected to
// fail) and its SettingsFile: the roles anyone can get per site and the
// client's email domains.
type Repo struct {
	Plugins, MuPlugins, Dropins map[string]bool
	PatchedPlugins              map[string]bool
	PatchedCore                 bool
	PublicRoles                 map[string][]string
	ClientDomains               []string
	// PublicUploads are folders under uploads ("models/product-3d", or
	// "sites/2/…" on a multisite) whose documents are public on purpose.
	PublicUploads []string
	// WPOrgPlugins are the wordpress.org slugs of the plugins it deploys
	// from wordpress.org (wp-plugin/ or wpackagist-plugin/ packages).
	WPOrgPlugins []string
	// Revision is the checkout's commit; Local its composer install's PHP
	// files hashed like the server's (nil, with LocalWhy, when there's none).
	Revision string
	Local    map[string]string
	LocalWhy string
	// Dir is the checkout when it has a composer install (Has).
	Dir string
	// Tracked are the files git tracks at TrackedAt, the deployed commit,
	// when the checkout is at another one (LoadTracked): what the release
	// ships from the repo itself, whatever the working tree holds.
	Tracked   map[string]bool
	TrackedAt string
	dir       string // the checkout, install or not
}

// LoadTracked reads the files git tracks at commit rev (one ls-tree), for a
// checkout that isn't at it, else GitHub's tree of that commit (gh, read
// only) when the checkout hasn't fetched it. Neither leaves Tracked nil:
// nothing is fetched into the checkout.
func (r *Repo) LoadTracked(rev string) {
	if r == nil || r.dir == "" || rev == "" {
		return
	}
	var paths []string
	if out, err := exec.Command("git", "-C", r.dir, "ls-tree", "-r", "-z", "--name-only", rev+"^{commit}").Output(); err == nil {
		paths = strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	} else {
		// {owner}/{repo} is the checkout's own, by gh. The first line says
		// whether GitHub cut the tree short; then one path per line.
		cmd := exec.Command("gh", "api", "repos/{owner}/{repo}/git/trees/"+rev+"?recursive=1",
			"--jq", `.truncated, (.tree[] | select(.type == "blob") | .path)`)
		cmd.Dir = r.dir
		out, err := cmd.Output()
		if err != nil {
			return
		}
		lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
		if len(lines) == 0 || lines[0] != "false" {
			return
		}
		paths = lines[1:]
	}
	r.Tracked, r.TrackedAt = make(map[string]bool, len(paths)), rev
	for _, p := range paths {
		r.Tracked[p] = true
	}
}

// Has reports whether the checkout's install has a file at path p (from the
// root): a data file it has is the release's own (a plugin's sample CSV).
func (r *Repo) Has(p string) bool {
	if r == nil || r.Dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(r.Dir, filepath.FromSlash(p)))
	return err == nil
}

// publicUpload reports whether rest, a path below uploads, is in one of the
// repo's PublicUploads folders.
func (r *Repo) publicUpload(rest string) bool {
	return r != nil && slices.ContainsFunc(r.PublicUploads, func(d string) bool {
		d = strings.Trim(d, "/")
		return d != "" && strings.HasPrefix(rest, d+"/")
	})
}

// Comparable reports whether the release can be compared with the local
// install: there is one, at the deployed commit or at one that installs the
// same files.
func (r *Repo) Comparable(deployed string) bool {
	return r != nil && r.Dir != "" &&
		(deployed == "" || strings.HasPrefix(r.Revision, deployed) || SameFiles(r.Dir, deployed))
}

// HashInstall hashes the composer install's PHP files like the server's, for
// the release comparison (Local). It's the slow part of reading a checkout,
// so it's separate: a run hashes while the site's scripts run, and one that
// skips the file checks doesn't hash at all.
func (r *Repo) HashInstall() {
	if r == nil || r.Dir == "" {
		return
	}
	var err error
	if r.Local, err = hashTree(r.Dir); err != nil {
		r.Local, r.LocalWhy = nil, "hashing the checkout: "+err.Error()
	}
}

// ReadRepo reads a Bedrock checkout: what it deploys (Composer packages by
// their installer path, plus what git tracks under web/app) and its
// SettingsFile. The checkout should be at the deployed commit: a branch that
// adds or drops a plugin shows up as a flag. Local stays nil until
// HashInstall.
func ReadRepo(dir string) (*Repo, error) {
	exp := &Repo{Plugins: map[string]bool{}, MuPlugins: map[string]bool{}, Dropins: map[string]bool{}, PatchedPlugins: map[string]bool{}, dir: dir}

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
		PublicUploads []string            `json:"public_uploads"`
	}
	if err := readJSON(filepath.Join(dir, SettingsFile), &settings); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	exp.PublicRoles = settings.PublicRoles
	exp.ClientDomains = settings.ClientDomains
	exp.PublicUploads = settings.PublicUploads
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
		if vendor, slug, _ := strings.Cut(p.Name, "/"); p.Type == "wordpress-plugin" && (vendor == "wp-plugin" || vendor == "wpackagist-plugin") {
			exp.WPOrgPlugins = append(exp.WPOrgPlugins, slug)
		}
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
	} else {
		exp.Dir, exp.LocalWhy = dir, "the checkout's install wasn't hashed"
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

// phpFile is what the hasher hashes: the same rule as hasher.sh's find.
var phpFile = regexp.MustCompile(`(?i)\.(php\d?|phtml|phar|pht|phps|inc)$`)

// hashTree hashes a composer install's PHP files the way hasher.sh does on
// the server: core, vendor and the content dir, not uploads or Composer's
// generated autoloaders, symlinked folders not followed. The walk feeds a few
// workers that stream each file through the hash with a buffer of their own,
// so no file is ever read whole into memory.
func hashTree(dir string) (map[string]string, error) {
	paths := make(chan string, 256)
	var walkErr error
	go func() {
		defer close(paths)
		for _, root := range []string{ContentDir, "vendor", "web/wp"} {
			walkErr = filepath.WalkDir(filepath.Join(dir, root), func(p string, d fs.DirEntry, err error) error {
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
				if d.Type().IsRegular() && phpFile.MatchString(d.Name()) {
					paths <- rel
				}
				return nil
			})
			if walkErr != nil {
				return
			}
		}
	}()

	files := map[string]string{}
	var mu sync.Mutex
	var hashErr error
	var wg sync.WaitGroup
	for range min(runtime.GOMAXPROCS(0), 8) {
		wg.Go(func() {
			buf := make([]byte, 64<<10)
			h := sha256.New()
			for rel := range paths {
				sum, err := hashFile(filepath.Join(dir, filepath.FromSlash(rel)), h, buf)
				mu.Lock()
				if err != nil && hashErr == nil {
					hashErr = err
				}
				files[rel] = sum
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if err := cmp.Or(walkErr, hashErr); err != nil {
		return nil, err
	}
	return files, nil
}

// hashFile is a file's sha256 in hex, h and buf reused between files.
func hashFile(path string, h hash.Hash, buf []byte) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h.Reset()
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(buf[:0])), nil
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
