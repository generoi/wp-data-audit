<?php

/*
 * wp-data-audit hasher, piped to `wp eval-file - --skip-wordpress`: no
 * WordPress, plugin or theme code loads, so nothing on the site can change
 * what it reports. It lists every PHP file of the release (core, vendor,
 * plugins, mu-plugins, themes, drop-ins) and under uploads, with a short
 * sha256, and the deployed commit from Deployer's REVISION file. The Go side
 * compares them with a composer install of that commit.
 */

$wpda_root = '';
for ($d = getcwd(), $i = 0; $i < 5 && $d !== '/'; $d = dirname($d), $i++) {
    if (is_file("$d/composer.json") && (is_dir("$d/web/app") || is_dir("$d/wp-content"))) {
        $wpda_root = $d;
        break;
    }
}
$wpda_out = ['version' => 1, 'root' => $wpda_root, 'revision' => '', 'files' => (object) [], 'truncated' => false, 'errors' => []];
if ($wpda_root === '') {
    $wpda_out['errors'][] = 'no Bedrock or WordPress root above ' . getcwd();
} else {
    if (is_file("$wpda_root/REVISION")) {
        $wpda_out['revision'] = trim((string) file_get_contents("$wpda_root/REVISION"));
    }
    $content = is_dir("$wpda_root/web/app") ? 'web/app' : 'wp-content';
    $wpda_out['content'] = $content;
    // uploads on its own: Deployer symlinks it to a shared folder, and the
    // iterator doesn't descend into symlinks.
    $roots = [$content, "$content/uploads", 'vendor', is_dir("$wpda_root/web/wp") ? 'web/wp' : 'wp-includes'];
    if ($content === 'wp-content') {
        $roots[] = 'wp-admin';
    }
    $files = [];
    $max = 200000;
    foreach ($roots as $r) {
        $path = "$wpda_root/$r";
        if (! is_dir($path)) {
            continue;
        }
        try {
            $skip = $r === $content ? "$path/uploads" : '';
            $it = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
                fn ($f) => $f->getPathname() !== $skip // walked as its own root
            ));
            foreach ($it as $f) {
                if (! $f->isFile() || ! preg_match('/\.(php\d?|phtml|phar|pht|phps|inc)$/i', $f->getFilename())) {
                    continue;
                }
                $rel = substr($f->getPathname(), strlen($wpda_root) + 1);
                if (str_starts_with($rel, 'vendor/composer/')) {
                    continue; // Composer's generated autoloaders differ by install flags
                }
                if (count($files) >= $max) {
                    $wpda_out['truncated'] = true;
                    break 2;
                }
                $h = @hash_file('sha256', $f->getPathname());
                $size = (int) $f->getSize();
                $v = $h === false ? 'unreadable' : substr($h, 0, 16) . ':' . $size;
                // An empty file or a "Silence is golden" directory guard is harmless.
                if ($size === 0 || ($size <= 200 && stripos((string) @file_get_contents($f->getPathname()), 'silence is golden') !== false)) {
                    $v .= ':silence';
                }
                $files[$rel] = $v;
            }
        } catch (Throwable $e) {
            $wpda_out['errors'][] = "$r: " . $e->getMessage();
        }
    }
    ksort($files);
    $wpda_out['files'] = (object) $files;
}
echo "\nWPDA-BEGIN\n" . json_encode($wpda_out, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\nWPDA-END\n";
