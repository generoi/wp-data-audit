# wp-data-audit

A light, read-only security audit of a WordPress site's data, meant to run
during monthly maintenance. Two scripts are piped over SSH (nothing is
installed or written on the site): a PHP collector through the site's own
`vendor/bin/wp eval-file -`, reading the database with plugins and themes
unloaded, and a shell hasher (`hasher.sh`) that lists the release's PHP files
with the server's own `find` and `sha256sum` in an empty environment, so no
code from the release runs for it. Go compares their facts with a composer
install of the deployed commit, the previous run and the flags a person has
accepted. No model is involved: a clean site costs nothing to check.

What it can't see past: the collector loads core, mu-plugins, drop-ins and
the site's wp-cli, so the report says when any of those differ from the
release (its other findings could then be forged); and the site user's shell
startup files run before the hasher, so an attacker who has that user's home
and targets this tool specifically could still interfere.

It flags:

- a role anyone can get whose definition grants more than reading
- accounts with a role the public can't get: new ones or changed roles
  urgently, email domains outside the staff and client domains. Only
  `customer` on WooCommerce sites and the roles a repo's `data-audit.json` declares are public,
  so a subscriber on a site without sign-ups is flagged too
- listed accounts not used in over a year. WordPress keeps no last login, so
  this is the newest of: a session's login, WooCommerce's or a plugin's
  last-activity meta, an application password's last use, and every earlier
  audit's (a login seen once is remembered). With none on record, a phpass
  password hash counts: since WordPress 6.8 (April 2025) a password login
  rehashes it, so a phpass hash means no password login since then
- staff-domain accounts whose address isn't on the config's `staff_emails`
  (people who left, aliases, shared addresses)
- capabilities granted outside a user's roles (role injection)
- open registration, urgently when the default role can do more than read
- application passwords and WooCommerce REST API keys
- login sessions of listed accounts from countries outside the allowed list,
  except allowed IPs (local DB-IP Lite lookup, no IP leaves the machine)
- changes to `siteurl`, `home` and `admin_email`
- PHP files under uploads; plugins, mu-plugins and drop-ins the repo doesn't
  deploy
- every PHP file of the release (core, `vendor/`, plugins including premium
  ones, mu-plugins, themes, drop-ins) that differs from a composer install of
  the deployed commit, one flag per package or theme. The deployed commit is
  GitHub's last successful `deploy_production.yml` run, else Deployer's
  `REVISION` file; a checkout a few commits ahead still counts
  when nothing deployed changed in between. Without a local install it falls
  back to wordpress.org's checksums for core and wp.org plugins. Compiled
  caches, built `build/` files and WordPress's own translation updates can't
  be compared and are only counted
- scripts, iframes, `javascript:` and `data:` URLs, PHP calls and hidden links in
  posts, meta, options, terms and approved comments, plain or encoded
- files anyone can download that shouldn't be public: database dumps,
  backups, archives, logs, keys, `.git`, and documents and exports (`csv`,
  `xls*`, `pdf`, `doc*`, …) in plugin folders under uploads or outside the
  media library, or anywhere under a name that suggests people's data
  (customers, members, orders, applications, in English, Finnish and
  Swedish). The hasher lists only size, date and path; the audit then asks
  each file's public URL with a HEAD request, so a file a plugin's
  `.htaccess` was meant to protect (which nginx ignores) shows as served.
  Served files and listed folders are urgent, one flag per plugin folder
  (`uploads/wpallexport/exports`); risky files the URL doesn't serve are for
  review, and a media library upload with a telling name only for review.
  Media library uploads, Gravity Forms uploads, plugin JSON and folders a
  plugin serves on purpose (Complianz) are only counted. On a multisite each
  site's uploads are asked for on that site's own domain
- what each site's public URL gives away: the REST API listing users,
  `?author=1` redirecting to a login slug, XML-RPC answering, the uploads
  folder listed, missing security headers (HSTS, framing, nosniff), a TLS
  certificate expiring within two weeks. Documentation and test domains
  (`example.com`, `.test`, …) are never asked
- personal data kept with no end: Gravity Forms forms with entries over two
  years old and no retention period, and shops with orders over two years old
  that never anonymise completed orders. Only counts and dates are collected

On a multisite every site is covered; facts from sites other than the main
one are tagged with their blog id, and network admins show as `super_admin`.

Users with only public roles are only counted. Content is never copied,
only the match (a script's host, an iframe's host, an inline script cut short),
so one accepted value is accepted wherever it appears.

## Use

From a Bedrock site's checkout at the deployed commit, after `composer
install` (for the file comparison; `gh` finds the deployed commit):

```sh
wp-data-audit geoip-update        # once a month
wp-data-audit                     # audits @production; exit 1 when there are flags
wp-data-audit accept <id>...      # an expected flag stays quiet until what it describes changes
wp-data-audit --env local --wp "ddev wp" --sh "ddev exec sh -s"   # try it on the local copy
```

The first run lists everything there is (all admins, every embed): accept the
expected ones once, and later runs show only what's new or changed.

What's true for one site lives in its repo, in `data-audit.json` at the root
(not composer.json: Composer's lock hash covers `extra`). `public_roles` keys
are a site's host, or its blog id on a multisite:

```json
{
  "public_roles": { "members.example": ["subscriber"] },
  "client_domains": ["client.example"]
}
```

What's true for every site lives in `~/.config/wp-data-audit/config.json`:

```json
{
  "allowed_countries": ["FI", "SE"],
  "allowed_ips": ["198.51.100.7", "203.0.113.0/24"],
  "staff_domains": ["agency.example"]
}
```

Snapshots, the last report and accepted flags live in
`~/.local/state/wp-data-audit/<site>/<env>/`, owner-only (they hold staff
emails and login IPs).

## As a library

`runner.Prepare` reads the repo and returns the two scripts to pipe however
you reach the site (`Run.Script` to wp-cli with `audit.WPArgs`, `Run.Hasher`
to `audit.HasherCommand` after a `cd` into the release); `Run.Finish` judges both outputs and saves snapshot and
report in the same state the CLI uses, and `runner.Accept` records a
decision. Set `Target.Deployed` (`runner.DeployedCommit`) when the server has
no `REVISION` file. Underneath,
`audit.Script`, `audit.Parse`, `audit.ReadRepo` and `audit.Check` do one step
each. `Flag.Untrusted` is text from the site, possibly written by an attacker:
show it as data, and keep accepting flags a person's decision.

## Licence

MIT. IP geolocation by [DB-IP](https://db-ip.com), CC BY 4.0.
