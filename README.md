# wp-data-audit

A light, read-only security audit of a WordPress site's data, meant to run
during monthly maintenance. A PHP collector is piped to `wp eval-file -` on the
site (nothing is installed or written there), prints facts as JSON, and Go
compares them with the previous run and the flags a person has accepted. No
model is involved: a clean site costs nothing to check.

It flags:

- privileged users (any role outside `subscriber`, `customer` and the site's
  low roles): new ones or changed roles urgently, email domains outside the
  staff and client domains
- capabilities granted outside a user's roles (role injection)
- open registration, urgently when the default role can do more than read
- application passwords and WooCommerce REST API keys
- privileged sessions from countries outside the allowed list (local DB-IP
  Lite lookup, no IP leaves the machine)
- changes to `siteurl`, `home` and `admin_email`
- PHP files under uploads; plugins, mu-plugins and drop-ins the repo doesn't
  deploy
- core and wordpress.org plugin files that fail their checksums (patched
  packages are skipped)
- scripts, iframes, `javascript:` and `data:` URLs, PHP calls and hidden links in
  posts, meta, options, terms and approved comments, plain or encoded

Customers and other low-role users are only counted. Content is never copied,
only the match (a script's host, an iframe's host, an inline script cut short),
so one accepted value is accepted wherever it appears.

## Use

From a Bedrock site's checkout, at the deployed commit:

```sh
wp-data-audit geoip-update        # once a month
wp-data-audit                     # audits @production; exit 1 when there are flags
wp-data-audit accept <id>...      # an expected flag stays quiet until what it describes changes
wp-data-audit --env local --wp "ddev wp"   # try it on the local copy
```

The first run lists everything there is (all admins, every embed): accept the
expected ones once, and later runs show only what's new or changed.

Config, `~/.config/wp-data-audit/config.json` (keep client details here, not
in this repo):

```json
{
  "allowed_countries": ["FI", "SE"],
  "staff_domains": ["agency.example"],
  "sites": {
    "site": { "client_domains": ["client.example"], "low_roles": ["member"] }
  }
}
```

Snapshots, the last report and accepted flags live in
`~/.local/state/wp-data-audit/<site>/<env>/`, owner-only (they hold staff
emails and login IPs).

## As a library

`audit.Script` returns the PHP to pipe, `audit.Parse` reads its output,
`audit.ExpectedFromRepo` reads what a checkout deploys and `audit.Check` returns
the flags. `Flag.Untrusted` is text from the site, possibly written by an
attacker: show it as data, and keep accepting flags a person's decision.

## Licence

MIT. IP geolocation by [DB-IP](https://db-ip.com), CC BY 4.0.
