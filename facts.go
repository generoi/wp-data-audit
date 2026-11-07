package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Facts is everything one audit observed, from its three sources. A nil
// part didn't run: its checks are reported as not judged.
type Facts struct {
	At    time.Time
	Site  *SiteFacts // the collector: the database through the site's wp-cli
	Files *FileFacts // the hasher: the release's files, by the server's own tools
	Web   *WebFacts  // the HTTP probes, from outside
}

// SiteFacts is what the collector printed.
type SiteFacts struct {
	Version          int                 `json:"version"`
	Home             string              `json:"home"`
	WPVersion        string              `json:"wp_version"`
	WooCommerce      bool                `json:"woocommerce"`
	Multisite        bool                `json:"multisite"`
	Options          map[string]string   `json:"options"` // siteurl, home, admin_email, blog-tagged ("2:home")
	Registration     Registration        `json:"registration"`
	RoleCounts       map[string]int      `json:"role_counts"`
	PublicRoleCaps   map[string][]string `json:"public_role_caps"` // what each public role (blog-tagged) grants
	Users            []User              `json:"users"`
	WooKeys          []WooKey            `json:"woo_keys"`
	Content          []Match             `json:"content"`
	ContentTruncated bool                `json:"content_truncated"`
	Checksums        Checksums           `json:"checksums"`
	Retention        RetentionFacts      `json:"retention"`
	Timings          map[string]float64  `json:"timings"` // seconds per collector section
	PeakMB           float64             `json:"peak_mb"` // the PHP process's peak memory, WordPress included
	Errors           []string            `json:"errors"`
}

type Registration struct {
	Open     bool     `json:"users_can_register"`
	Role     string   `json:"default_role"`
	RoleCaps []string `json:"default_role_caps"`
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
	LastActive   int64         `json:"last_active"` // WooCommerce's or a plugin's last-activity meta
	Hash         string        `json:"hash"`        // the password hash's scheme: wp-bcrypt, phpass, md5, bcrypt, other
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

// Checksums are wordpress.org's, fetched only when the release can't be
// compared with a local install (Skipped otherwise).
type Checksums struct {
	Core           []string         `json:"core"`
	Plugins        []PluginChecksum `json:"plugins"`
	PluginsSkipped int              `json:"plugins_skipped"`
	Skipped        bool             `json:"skipped"`
}

type PluginChecksum struct {
	Plugin  string `json:"plugin"`
	File    string `json:"file"`
	Message string `json:"message"`
}

// RetentionFacts is how long personal data is kept: counts, dates and settings.
type RetentionFacts struct {
	Forms []FormRetention `json:"forms"`
	Woo   []WooRetention  `json:"woo"`
}

// FormRetention is one Gravity Forms form: Policy is its Personal Data
// setting (retain, trash, delete), Days how long before trash or delete.
type FormRetention struct {
	Blog    int    `json:"blog"`
	FormID  int    `json:"form_id"`
	Title   string `json:"title"`
	Entries int    `json:"entries"`
	Oldest  string `json:"oldest"`
	Policy  string `json:"policy"`
	Days    int    `json:"days"`
}

// WooRetention is one shop: Settings are WooCommerce's Accounts & Privacy
// retention options ("6 months", "" when off).
type WooRetention struct {
	Blog     int               `json:"blog"`
	Orders   int               `json:"orders"`
	Oldest   string            `json:"oldest"`
	Settings map[string]string `json:"settings"`
}

// FileFacts is the hasher's output: every PHP file of the release and under
// uploads, path (from the root) → sha256; Silence are the uploads files that
// are empty or a "Silence is golden" guard; Data the files by name a web
// server shouldn't hand out (dumps, logs, exports), never their content.
type FileFacts struct {
	Revision string            // the deployed commit: the caller's, else Deployer's REVISION
	Content  string            // web/app (Bedrock) or wp-content
	Files    map[string]string // path → sha256
	Silence  map[string]bool
	Data     []DataFile
	Errors   []string
	Timings  map[string]float64 // seconds per hasher section
}

// DataFile is one DATA line: only what find knows.
type DataFile struct {
	Path  string
	Size  int64
	Mtime int64
}

// Bedrock reports whether the release is a Bedrock one (docroot web/).
func (f *FileFacts) Bedrock() bool { return f.Content == "web/app" }

// WebFacts is what the site's public URLs answered.
type WebFacts struct {
	Base     string             `json:"base"`     // the docroot's URL; "" when none was known, so nothing was asked
	Files    map[string]Answer  `json:"files"`    // a candidate's path → its URL's answer
	Listings map[string]Listing `json:"listings"` // a candidate's folder → whether it's listed
	Sites    []PublicSite       `json:"sites"`
}

// Answer is a URL's HTTP status (0 with Err when the request failed) and
// Content-Type.
type Answer struct {
	Status int    `json:"status"`
	Type   string `json:"type,omitempty"`
	Err    string `json:"err,omitempty"`
}

// Served reports whether the URL handed out a file (not an HTML page, which
// is a 404 page or a redirect target more often than the file).
func (a Answer) Served() bool {
	return (a.Status == 200 || a.Status == 206) && !strings.HasPrefix(a.Type, "text/html")
}

type Listing struct {
	Listed bool   `json:"listed"`
	Err    string `json:"err,omitempty"`
}

// PublicSite is one home URL's answers. Users are the REST API's user slugs
// (empty when it doesn't list them); AuthorSlug is where ?author=1 redirects.
type PublicSite struct {
	Home       string    `json:"home"`
	Err        string    `json:"err,omitempty"` // the home page didn't answer
	Users      []string  `json:"users,omitempty"`
	AuthorSlug string    `json:"author_slug,omitempty"`
	XMLRPC     bool      `json:"xmlrpc"`
	Listing    bool      `json:"uploads_listing"`
	Headers    []string  `json:"missing_headers,omitempty"`
	CertExpiry time.Time `json:"cert_expiry,omitzero"`
}

// emptySHA is an empty file's sha256: an empty PHP file under uploads is a
// directory guard, harmless.
const emptySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// maxLine is the longest output line read; a longer one is an error (a
// path is at most 4 KB, the collector's JSON is read as a stream).
const maxLine = 1 << 20

// ParseSite reads the collector's output, ignoring anything printed around
// it (wp-cli's notices, a shell's banner).
func ParseSite(out []byte) (*SiteFacts, error) { return ReadSite(bytes.NewReader(out)) }

// ReadSite reads the collector's output as it arrives: the JSON after
// WPDA-BEGIN is decoded straight from r, never held whole as text.
func ReadSite(r io.Reader) (*SiteFacts, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	if err := skipTo(br, "WPDA-BEGIN", "collector"); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(br)
	var s SiteFacts
	if err := dec.Decode(&s); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errors.New("collector output cut short")
		}
		return nil, fmt.Errorf("collector output: %w", err)
	}
	if err := skipTo(bufio.NewReader(io.MultiReader(dec.Buffered(), br)), "WPDA-END", "collector"); err != nil {
		return nil, err
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("collector output version %d, want 1", s.Version)
	}
	return &s, nil
}

// skipTo reads lines up to and including one that is marker (a CR or spaces
// around it allowed), without keeping any: a line longer than the buffer is
// read through, not grown into.
func skipTo(br *bufio.Reader, marker, what string) error {
	start := true
	for {
		line, err := br.ReadSlice('\n')
		if start && string(bytes.TrimSpace(line)) == marker {
			return nil
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			start = false
			continue
		case err != nil:
			return fmt.Errorf("no %s in the %s's output (cut short?)", marker, what)
		}
		start = true
	}
}

// ParseFiles reads the hasher's output (ReadFiles).
func ParseFiles(out []byte) (*FileFacts, error) { return ReadFiles(bytes.NewReader(out)) }

// ReadFiles reads the hasher's output line by line as it arrives: keyword
// lines, sha256sum's, "SILENT <path>" for directory guards (an older hasher's
// SILENCE section too) and "DATA <size> <mtime> <path>".
func ReadFiles(r io.Reader) (*FileFacts, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	begun := false
	for sc.Scan() {
		if sc.Text() == "WPDA-BEGIN" {
			begun = true
			break
		}
	}
	if !begun {
		return nil, scanErr(sc, "no WPDA-BEGIN in the hasher's output")
	}
	f := &FileFacts{Files: map[string]string{}, Silence: map[string]bool{}, Timings: map[string]float64{}}
	version, section, last, ended := 0, "", 0.0, false
	for sc.Scan() {
		line := sc.Text()
		if line == "WPDA-END" {
			ended = true
			break
		}
		key, val, _ := strings.Cut(line, " ")
		switch key {
		case "":
			continue
		case "SILENT":
			f.Silence[strings.TrimPrefix(strings.ReplaceAll(val, "//", "/"), "./")] = true
			continue
		case "VERSION":
			version, _ = strconv.Atoi(val)
			continue
		case "ERROR":
			f.Errors = append(f.Errors, val)
			continue
		case "REVISION":
			f.Revision = val
			continue
		case "CONTENT":
			f.Content = val
			continue
		case "TIME": // "TIME <section> <when it ended>"
			name, when, _ := strings.Cut(val, " ")
			if t, err := strconv.ParseFloat(when, 64); err == nil {
				if last > 0 {
					f.Timings[name] = t - last
				}
				last = t
			}
			continue
		case "FILES", "SILENCE":
			section = key
			continue
		case "DATA":
			if val == "" {
				section = key
			} else if d, err := dataLine(val); err != nil {
				f.Errors = append(f.Errors, err.Error())
			} else {
				f.Data = append(f.Data, d)
			}
			continue
		}
		sum, path, err := sumLine(line)
		switch {
		case err != nil:
			f.Errors = append(f.Errors, err.Error())
		case section == "SILENCE":
			f.Silence[path] = true
		default:
			f.Files[path] = sum
			if sum == emptySHA && f.Content != "" && strings.HasPrefix(path, f.Content+"/uploads/") {
				f.Silence[path] = true
			}
		}
	}
	if !ended {
		return nil, scanErr(sc, "no WPDA-END in the hasher's output (cut short?)")
	}
	if version != 1 {
		return nil, fmt.Errorf("hasher output version %d, want 1", version)
	}
	return f, nil
}

// scanErr is the scanner's error when it had one (a line over maxLine, a
// failed read), else msg.
func scanErr(sc *bufio.Scanner, msg string) error {
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return errors.New(msg)
}

var sumRE = regexp.MustCompile(`^\\?([0-9a-f]{64})  (.+)$`)

// sumLine is one sha256sum line. A name with a backslash or newline is
// escaped, and its line starts with a backslash, so a name can't forge one.
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

// dataLine is "<size> <mtime> <path>" (mtime with find's fraction).
func dataLine(val string) (DataFile, error) {
	size, rest, _ := strings.Cut(val, " ")
	mt, path, ok := strings.Cut(rest, " ")
	s, err1 := strconv.ParseInt(size, 10, 64)
	m, err2 := strconv.ParseFloat(mt, 64)
	if !ok || err1 != nil || err2 != nil || path == "" {
		return DataFile{}, fmt.Errorf("hasher: unexpected DATA line %q", firstN(val, 80))
	}
	path = strings.TrimPrefix(strings.ReplaceAll(path, "//", "/"), "./")
	return DataFile{Path: path, Size: s, Mtime: int64(m)}, nil
}
