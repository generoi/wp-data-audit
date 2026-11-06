// Package geo looks up IP countries in a local DB-IP Lite database, so no IP
// leaves the machine. Update downloads it (CC BY 4.0, https://db-ip.com).
package geo

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// DB is an open country database.
type DB struct{ r *maxminddb.Reader }

// DefaultPath is where Update puts the database.
func DefaultPath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "wp-data-audit", "dbip-country-lite.mmdb")
}

// Open opens the database at path.
func Open(path string) (*DB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &DB{r: r}, nil
}

// Close releases the database.
func (d *DB) Close() error { return d.r.Close() }

// Country is the IP's ISO country code, "" when unknown or not an IP.
func (d *DB) Country(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := d.r.Lookup(addr).Decode(&rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}

// Update downloads this month's database to path, falling back to last
// month's early in a month, before the new one is published.
func Update(ctx context.Context, path string) error {
	now := time.Now().UTC()
	var last error
	for _, t := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := fmt.Sprintf("https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz", t.Format("2006-01"))
		if last = download(ctx, url, path); last == nil {
			return nil
		}
	}
	return last
}

func download(ctx context.Context, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, res.Status)
	}
	gz, err := gzip.NewReader(res.Body)
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dbip-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, gz); err != nil {
		tmp.Close()
		return fmt.Errorf("%s: %w", url, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	db, err := Open(tmp.Name()) // never replace a good database with a bad one
	if err != nil {
		return fmt.Errorf("%s: not a database: %w", url, err)
	}
	db.Close()
	return os.Rename(tmp.Name(), path)
}
