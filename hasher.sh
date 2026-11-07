# wp-data-audit hasher, piped to `sh -s` over SSH in the release (or any
# folder below it). Only the system's own find, sha256sum and grep run:
# nothing from the release, not even its wp-cli, so a compromised site can't
# change what this reports. It lists every PHP file of the release (core,
# vendor, plugins, mu-plugins, themes, drop-ins) and under uploads with its
# sha256, and the deployed commit from Deployer's REVISION file when there is
# one. sha256sum escapes odd file names (a leading backslash), so a name
# can't forge a line; the Go side compares the list with a composer install.
set -u
set -f # the name patterns below are find's, never the shell's
PATH=/usr/bin:/bin # the system's tools, whatever the caller's PATH was
export PATH
# The lowest CPU and disk priority, inherited by every find and sha256sum:
# the site's visitors come first. Where either tool is missing it runs as is.
renice -n 19 -p $$ >/dev/null 2>&1
ionice -c 2 -n 7 -p $$ >/dev/null 2>&1
root=$(pwd)
while [ "$root" != / ] && ! { [ -f "$root/composer.json" ] && { [ -d "$root/web/app" ] || [ -d "$root/wp-content" ]; }; }; do
	root=$(dirname "$root")
done
echo
echo WPDA-BEGIN
echo "VERSION 1"
if [ "$root" = / ]; then
	echo "ERROR no Bedrock or WordPress root above $(pwd)"
	echo WPDA-END
	exit 0
fi
cd "$root" || exit 0
if ! command -v sha256sum >/dev/null; then
	echo "ERROR no sha256sum on the server"
	echo WPDA-END
	exit 0
fi
[ -f REVISION ] && echo "REVISION $(head -c 64 REVISION | tr -cd '0-9a-f')"
content=web/app core=web/wp
[ -d web/app ] || { content=wp-content core="wp-includes wp-admin"; }
echo "CONTENT $content"
# mark SECTION: when SECTION ended (the Go side turns marks into durations).
mark() { echo "TIME $1 $(date +%s.%N)"; }
mark start

# What find looks for, by name only (no PHP binary runs here). Unquoted where
# used: split on spaces, never globbed (set -f).
php="-iname *.php -o -iname *.php[0-9] -o -iname *.phtml -o -iname *.phar -o -iname *.pht -o -iname *.phps -o -iname *.inc"
# Files the web server may hand out that shouldn't be public: dumps, backups,
# archives, logs, keys (anywhere in the docroot) ...
risky="-iname *.sql -o -iname *.sql.* -o -iname *.dump -o -iname *.sqlite -o -iname *.sqlite3
	-o -iname *.db -o -iname *.mdb -o -iname *.bak -o -iname *.backup -o -iname *.old
	-o -iname *.orig -o -iname *.save -o -iname *.swp -o -iname *~ -o -iname *.log
	-o -iname .env -o -iname .env.* -o -iname *.env -o -iname *.key -o -iname *.pem
	-o -iname *.p12 -o -iname *.pfx -o -iname *.zip -o -iname *.tar -o -iname *.tar.*
	-o -iname *.tgz -o -iname *.7z -o -iname *.rar -o -iname *.wpress -o -iname wp-config*
	-o -path */.git/config"
# ... and documents and data exports (outside plugins, themes and core, which
# ship their own samples, and the translations and caches WordPress and
# plugins write). Only size, mtime and path: never a byte of content.
documents="-iname *.csv -o -iname *.tsv -o -iname *.xls -o -iname *.xlsx -o -iname *.xlsm
	-o -iname *.ods -o -iname *.pdf -o -iname *.doc -o -iname *.docx -o -iname *.odt
	-o -iname *.rtf -o -iname *.xml -o -iname *.json"
data="-printf DATA\040%s\040%T@\040%p\n"
# Names a line can't carry (a newline or backslash) are left out of DATA and
# SILENT lines: sha256sum escapes them, printf doesn't. Inline where used, as
# a newline can't sit in a word-split variable.
nl='
'

# The release's PHP files, minus uploads (walked on its own below) and
# Composer's generated autoloaders.
echo FILES
# shellcheck disable=SC2086 # the variables are this script's own find arguments
find "$content" vendor $core \( -path "$content/uploads" -o -path vendor/composer \) -prune -o -type f \( $php \) -exec sha256sum {} + 2>/dev/null
mark release

if [ -d web/app ]; then docroot=web pre=; else docroot=. pre=./; fi
shipped=""
for d in "$content/plugins" "$content/themes" "$content/mu-plugins" "$content/languages" "$content/cache" $core vendor; do
	shipped="$shipped -path $pre$d/* -o"
done
# The docroot outside uploads, in one walk: risky files anywhere, documents
# outside the folders above (excluded by path: a prune would end the walk
# there for both). `,` lets one file be both.
# shellcheck disable=SC2086
find "$docroot" \( -path "$pre$content/uploads" -o -name node_modules \) -prune -o -type f ! -name "*$nl*" ! -name '*\\*' \
	\( \( $risky \) $data , ! \( $shipped -false \) \( $documents \) $data \) 2>/dev/null
mark docroot

# Uploads, the folder that grows: one walk for all of it. Its PHP files are
# hashed (empty ones the Go side knows by their hash), "Silence is golden"
# directory guards named, and its risky files and documents listed.
if [ -d "$content/uploads/" ]; then
	# The trailing slash follows a deploy's shared-folder symlink.
	# shellcheck disable=SC2086
	find "$content/uploads/" -type f \( \
		\( $php \) -exec sha256sum {} + \
		, \( $php \) ! -name "*$nl*" ! -name '*\\*' -size -201c ! -empty -exec grep -qis 'silence is golden' {} \; -printf 'SILENT %p\n' \
		, ! -name "*$nl*" ! -name '*\\*' \( $risky -o $documents \) $data \
		\) 2>/dev/null
	mark uploads
fi
echo WPDA-END
