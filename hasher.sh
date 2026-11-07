# wp-data-audit hasher, piped to `sh -s` over SSH in the release (or any
# folder below it). Only the system's own find, sha256sum and grep run:
# nothing from the release, not even its wp-cli, so a compromised site can't
# change what this reports. It lists every PHP file of the release (core,
# vendor, plugins, mu-plugins, themes, drop-ins) and under uploads with its
# sha256, and the deployed commit from Deployer's REVISION file when there is
# one. sha256sum escapes odd file names (a leading backslash), so a name
# can't forge a line; the Go side compares the list with a composer install.
set -u
PATH=/usr/bin:/bin # the system's tools, whatever the caller's PATH was
export PATH
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

# php_files DIR... [TESTS]: the PHP files under DIR (by name: no PHP binary
# runs here), minus uploads and Composer's generated autoloaders (walked on
# their own, or not at all), then TESTS.
php_files() {
	dirs=""
	while [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; do dirs="$dirs $1"; shift; done
	# shellcheck disable=SC2086 # dirs are this script's own, no spaces
	find $dirs \( -path "$content/uploads" -o -path vendor/composer \) -prune -o -type f \
		\( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.pht' -o -iname '*.phps' -o -iname '*.inc' \) \
		"$@" 2>/dev/null
}

echo FILES
# shellcheck disable=SC2086
php_files "$content" vendor $core -exec sha256sum {} +
mark release
# The trailing slash follows a deploy's shared-folder symlink.
[ -d "$content/uploads/" ] && php_files "$content/uploads/" -exec sha256sum {} +
mark uploads-php
# Empty files and "Silence is golden" directory guards under uploads: harmless.
echo SILENCE
if [ -d "$content/uploads/" ]; then
	php_files "$content/uploads/" -empty -exec sha256sum {} +
	php_files "$content/uploads/" -size -201c ! -empty -exec grep -qis 'silence is golden' {} \; -exec sha256sum {} +
fi
mark uploads-silence

# Files the web server may hand out that shouldn't be public: dumps, backups,
# archives, logs, keys (anywhere in the docroot), and documents and data
# exports (outside plugins, themes and core, which ship their own samples,
# and the translations and caches WordPress and plugins write).
# Only size, mtime and path: never a byte of content. Names with a newline
# or backslash are left out so a name can't forge a line.
echo DATA
if [ -d web/app ]; then docroot=web pre=; else docroot=. pre=./; fi
nl='
'
risky() {
	find "$@" ! -name "*$nl*" ! -name '*\\*' -type f \( \
		-iname '*.sql' -o -iname '*.sql.*' -o -iname '*.dump' -o -iname '*.sqlite' -o -iname '*.sqlite3' \
		-o -iname '*.db' -o -iname '*.mdb' -o -iname '*.bak' -o -iname '*.backup' -o -iname '*.old' \
		-o -iname '*.orig' -o -iname '*.save' -o -iname '*.swp' -o -iname '*~' -o -iname '*.log' \
		-o -iname '.env' -o -iname '.env.*' -o -iname '*.env' -o -iname '*.key' -o -iname '*.pem' \
		-o -iname '*.p12' -o -iname '*.pfx' -o -iname '*.zip' -o -iname '*.tar' -o -iname '*.tar.*' \
		-o -iname '*.tgz' -o -iname '*.7z' -o -iname '*.rar' -o -iname '*.wpress' -o -iname 'wp-config*' \
		-o -path '*/.git/config' \) -printf 'DATA %s %T@ %p\n' 2>/dev/null
}
documents() {
	find "$@" ! -name "*$nl*" ! -name '*\\*' -type f \( \
		-iname '*.csv' -o -iname '*.tsv' -o -iname '*.xls' -o -iname '*.xlsx' -o -iname '*.xlsm' \
		-o -iname '*.ods' -o -iname '*.pdf' -o -iname '*.doc' -o -iname '*.docx' -o -iname '*.odt' \
		-o -iname '*.rtf' -o -iname '*.xml' -o -iname '*.json' \) -printf 'DATA %s %T@ %p\n' 2>/dev/null
}
risky "$docroot" \( -path "$pre$content/uploads" -o -name node_modules \) -prune -o
mark docroot-risky
prune=""
# shellcheck disable=SC2086 # core is this script's own, no spaces
for d in "$content/plugins" "$content/themes" "$content/mu-plugins" "$content/languages" "$content/cache" $core vendor; do
	prune="$prune -path $pre$d -o"
done
# shellcheck disable=SC2086
documents "$docroot" \( $prune -path "$pre$content/uploads" -o -name node_modules \) -prune -o
mark docroot-documents
if [ -d "$content/uploads/" ]; then
	risky "$content/uploads/"
	mark uploads-risky
	documents "$content/uploads/"
	mark uploads-documents
fi
echo WPDA-END
