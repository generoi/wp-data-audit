// Package ghzip fetches a GitHub repo's archive at a ref, the zip Composer
// installs a GitHub package from (export-ignore'd files left out), and hashes
// its files. Public repos only: no credentials are sent, so a private one
// answers 404 and is reported as not fetched. Each repo and ref is fetched
// once: its hashes are kept in a cache folder.
package ghzip

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	audit "github.com/generoi/wp-data-audit"
)

// Base is GitHub's archive host, outside the API's rate limit.
const Base = "https://codeload.github.com"

// maxZip is the largest archive read: far above any plugin's.
const maxZip = 256 << 20

// DefaultCache is where fetched archives' hashes are kept.
func DefaultCache() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "wp-data-audit", "github")
}

// safe matches a repo's owner or name, or a ref, that's safe as a path segment.
var safe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// Hashes fetches every package's archive, four at a time, by plugin folder.
// One that isn't on GitHub, or is patched on install, isn't asked for.
func Hashes(ctx context.Context, client *http.Client, base, cache string, pkgs map[string]audit.Package) map[string]audit.PackageFiles {
	out := map[string]audit.PackageFiles{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for folder, p := range pkgs {
		if p.Repo == "" || p.Patched {
			continue
		}
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			files, err := one(ctx, client, base, cache, p.Repo, p.Ref)
			pf := audit.PackageFiles{Files: files}
			if err != nil {
				pf = audit.PackageFiles{Err: err.Error()}
			}
			mu.Lock()
			out[folder] = pf
			mu.Unlock()
		})
	}
	wg.Wait()
	return out
}

// one is repo's archive at ref, hashed: from the cache, else fetched and
// then cached. A failed fetch isn't cached.
func one(ctx context.Context, client *http.Client, base, cache, repo, ref string) (map[string]string, error) {
	owner, name, _ := strings.Cut(repo, "/")
	if !safe.MatchString(owner) || !safe.MatchString(name) || !safe.MatchString(ref) {
		return nil, fmt.Errorf("unexpected repo or ref %q@%q", repo, ref)
	}
	path := filepath.Join(cache, owner, name, ref+".json")
	var files map[string]string
	if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &files) == nil {
		return files, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+repo+"/zip/"+ref, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wp-data-audit")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("not a public download (%s)", resp.Status)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("download: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxZip+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("download: %w", err)
	case len(b) > maxZip:
		return nil, fmt.Errorf("archive over %d MB", maxZip>>20)
	}
	if files, err = hashZip(b); err != nil {
		return nil, err
	}
	if err := write(path, files); err != nil {
		return nil, fmt.Errorf("caching: %w", err)
	}
	return files, nil
}

// hashZip hashes the archive's regular files, by path below its one top
// folder ("owner-name-sha/"), the plugin's own folder once installed.
func hashZip(b []byte) (map[string]string, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		_, rel, ok := strings.Cut(f.Name, "/")
		if !ok || rel == "" || !f.Mode().IsRegular() {
			continue
		}
		r, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("archive: %w", err)
		}
		h := sha256.New()
		_, err = io.Copy(h, r)
		r.Close()
		if err != nil {
			return nil, fmt.Errorf("archive: %s: %w", rel, err)
		}
		files[rel] = hex.EncodeToString(h.Sum(nil))
	}
	return files, nil
}

// write saves files to path atomically (a temp file, then a rename).
func write(path string, files map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(files)
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
