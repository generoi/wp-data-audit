package audit

import (
	"fmt"
	"strings"
)

// content: scripts, iframes, JavaScript and data URLs, PHP calls and hidden
// links in posts, meta, options, terms and comments. One flag per distinct
// value, so one accepted value (a GTM snippet, a YouTube iframe) is accepted
// wherever it appears.
func (c *checker) content() {
	s := c.in.Facts.Site
	for _, m := range s.Content {
		var where []string
		for _, x := range m.At {
			w := ""
			if s.Multisite {
				w = fmt.Sprintf("blog %d ", x.Blog)
			}
			switch {
			case x.Table == "options":
				w += "option " + x.Key
			case x.Key != "":
				w += fmt.Sprintf("%s %d %s", x.Table, x.ID, x.Key)
			default:
				w += fmt.Sprintf("%s %d %s", x.Table, x.ID, x.Field)
			}
			where = append(where, w)
		}
		if more := m.Count - len(m.At); more > 0 {
			where = append(where, fmt.Sprintf("and %d more", more))
		}
		msg := m.Kind + " in content"
		if m.Encoded {
			msg += " (encoded)"
		}
		c.flag(Flag{ID: "content:" + m.Hash, Severity: sev(m.Kind == "php-call" || m.Encoded), Kind: KindContent,
			Message: msg, Untrusted: m.Snippet + " | at " + strings.Join(where, "; ")})
	}
	if s.ContentTruncated {
		c.problem("content scan stopped at its limit: more matches than listed")
	}
}
