<?php

/*
 * wp-data-audit collector, piped to `wp eval-file -`. wp-data-audit puts
 * $wpda_public_roles above this file. Read-only: it changes nothing on the
 * site and prints facts as JSON between WPDA-BEGIN and WPDA-END. Judging them
 * is the Go side's job, so rules change without touching sites.
 *
 * Personal data is kept to what an audit needs. Public roles are the ones
 * anyone can get on a site: `customer` where WooCommerce runs, plus what the
 * repo declares per site (host or blog id => roles). Users holding only
 * public roles are counted; everyone else (and anyone with extra capabilities
 * or application passwords) is listed. Content is never printed, only what
 * matched, cut short.
 */

global $wpdb;

$wpda_public_roles = isset($wpda_public_roles) && is_array($wpda_public_roles) ? $wpda_public_roles : [];
$wpda_public = function (int $blog) use ($wpda_public_roles): array {
    $host = strtolower((string) parse_url(home_url(), PHP_URL_HOST));
    $roles = array_merge($wpda_public_roles[$host] ?? [], $wpda_public_roles[(string) $blog] ?? []);
    if (get_option('woocommerce_version')) {
        $roles[] = 'customer';
    }

    return $roles;
};
$wpda_errors = [];
$wpda_rows = 2000;    // per content query; reaching it marks the scan truncated
$wpda_max = 500;      // matches, upload files

// On a multisite, per-site facts (options, roles, content, WooCommerce keys)
// are collected for every site; anything from a site other than the main
// one is tagged "<blog id>:".
$wpda_main = is_multisite() ? (int) get_main_site_id() : (int) get_current_blog_id();
$wpda_blogs = is_multisite() ? array_map('intval', get_sites(['fields' => 'ids', 'number' => 0, 'deleted' => 0])) : [$wpda_main];
$wpda_tag = fn (int $blog, string $s): string => $blog === $wpda_main ? $s : "{$blog}:{$s}";
$wpda_each = function (callable $fn) use ($wpda_blogs) {
    foreach ($wpda_blogs as $blog) {
        is_multisite() && switch_to_blog($blog);
        try {
            $fn($blog);
        } finally {
            is_multisite() && restore_current_blog();
        }
    }
};

$wpda = [
    'version' => 1,
    'generated_at' => gmdate('c'),
    'home' => (string) get_option('home'),
    'wp_version' => (string) get_bloginfo('version'),
    'woocommerce' => class_exists('WooCommerce'),
    'multisite' => is_multisite(),
];

$wpda_options = [];
$wpda_each(function (int $blog) use (&$wpda_options, $wpda_tag) {
    foreach (['siteurl', 'home', 'admin_email'] as $name) {
        $wpda_options[$wpda_tag($blog, $name)] = (string) get_option($name);
    }
});
$wpda['options'] = (object) $wpda_options;

// Registration: the main site's default role; on a multisite, the network
// setting decides whether anyone can sign up.
$wpda_default_role = (string) get_option('default_role');
$wpda_role = get_role($wpda_default_role);
$wpda['registration'] = [
    'users_can_register' => is_multisite() ? in_array(get_site_option('registration'), ['user', 'all'], true) : (bool) get_option('users_can_register'),
    'default_role' => $wpda_default_role,
    'default_role_caps' => $wpda_role ? array_keys(array_filter($wpda_role->capabilities)) : [],
];

// Users: roles from each site's capabilities meta directly, so a capability
// granted outside any role (role injection) shows up as extra_caps.
$wpda_user_roles = [];
$wpda_privileged = [];
$wpda_detail = [];
$wpda_counts = [];
$wpda_each(function (int $blog) use ($wpdb, $wpda_tag, $wpda_public, &$wpda_user_roles, &$wpda_privileged, &$wpda_detail, &$wpda_counts) {
    $site_roles = wp_roles();
    $public = $wpda_public($blog);
    $capkey = $wpdb->get_blog_prefix() . 'capabilities';
    foreach ($wpdb->get_results($wpdb->prepare("SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s", $capkey)) as $row) {
        $caps = maybe_unserialize($row->meta_value);
        $roles = [];
        $extra = [];
        foreach (is_array($caps) ? $caps : [] as $cap => $on) {
            if (! $on) {
                continue;
            }
            if ($site_roles->is_role($cap)) {
                $roles[] = (string) $cap;
            } else {
                $extra[] = $wpda_tag($blog, (string) $cap);
            }
        }
        foreach ($roles ?: ['(none)'] as $r) {
            $k = $wpda_tag($blog, $r);
            $wpda_counts[$k] = ($wpda_counts[$k] ?? 0) + 1;
        }
        $id = (int) $row->user_id;
        foreach ($roles as $r) {
            $wpda_user_roles[$id][] = $wpda_tag($blog, $r);
        }
        if (array_diff($roles, $public)) {
            $wpda_privileged[$id] = true;
        }
        if (isset($wpda_privileged[$id]) || $extra) {
            $wpda_detail[$id] ??= ['extra_caps' => [], 'app_passwords' => []];
            array_push($wpda_detail[$id]['extra_caps'], ...$extra);
        }
    }
});
if (is_multisite()) {
    foreach (get_super_admins() as $login) {
        $u = get_user_by('login', $login);
        if ($u) {
            $wpda_user_roles[$u->ID][] = 'super_admin';
            $wpda_privileged[$u->ID] = true;
            $wpda_detail[$u->ID] ??= ['extra_caps' => [], 'app_passwords' => []];
        }
    }
}
$wpda['role_counts'] = (object) $wpda_counts;

foreach ($wpdb->get_results("SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = '_application_passwords'") as $row) {
    $list = maybe_unserialize($row->meta_value);
    if (! is_array($list) || ! $list) {
        continue;
    }
    $id = (int) $row->user_id;
    $wpda_detail[$id] ??= ['extra_caps' => [], 'app_passwords' => []];
    foreach ($list as $p) {
        $wpda_detail[$id]['app_passwords'][] = [
            'uuid' => (string) ($p['uuid'] ?? ''),
            'name' => (string) ($p['name'] ?? ''),
            'created' => (int) ($p['created'] ?? 0),
            'last_used' => (int) ($p['last_used'] ?? 0),
            'last_ip' => (string) ($p['last_ip'] ?? ''),
        ];
    }
}

$wpda['users'] = [];
foreach ($wpda_detail as $id => $d) {
    $u = get_userdata($id);
    if (! $u) {
        continue;
    }
    $roles = $wpda_user_roles[$id] ?? [];
    $sessions = [];
    $tokens = get_user_meta($id, 'session_tokens', true);
    foreach (is_array($tokens) ? $tokens : [] as $t) { // keys are token hashes: never printed
        if (is_array($t)) {
            $sessions[] = [
                'ip' => (string) ($t['ip'] ?? ''),
                'ua' => substr((string) ($t['ua'] ?? ''), 0, 200),
                'login' => (int) ($t['login'] ?? 0),
                'expiration' => (int) ($t['expiration'] ?? 0),
            ];
        }
    }
    usort($sessions, fn ($a, $b) => $b['login'] <=> $a['login']);
    $wpda['users'][] = [
        'id' => $id,
        'login' => (string) $u->user_login,
        'email' => (string) $u->user_email,
        'registered' => (string) $u->user_registered,
        'roles' => $roles,
        'privileged' => isset($wpda_privileged[$id]),
        'extra_caps' => $d['extra_caps'],
        'sessions' => array_slice($sessions, 0, 20),
        'app_passwords' => $d['app_passwords'],
    ];
}

// WooCommerce REST API keys, without the key or secret.
$wpda['woo_keys'] = [];
$wpda_each(function (int $blog) use ($wpdb, &$wpda) {
    $table = $wpdb->prefix . 'woocommerce_api_keys';
    if (! $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table)))) {
        return;
    }
    foreach ($wpdb->get_results("SELECT key_id, user_id, description, permissions, truncated_key, last_access FROM {$table}") as $k) {
        $wpda['woo_keys'][] = [
            'blog' => $blog,
            'key_id' => (int) $k->key_id,
            'user_id' => (int) $k->user_id,
            'description' => (string) $k->description,
            'permissions' => (string) $k->permissions,
            'truncated_key' => (string) $k->truncated_key,
            'last_access' => (string) $k->last_access,
        ];
    }
});

// Content. SQL prefilters with LIKE (one scan per table), PHP decodes and
// matches. A match is reported as kind + value: the script's host, the
// iframe's host, or the normalised inline code, so one accepted value (a GTM
// snippet, a YouTube iframe) is accepted wherever it appears.
$wpda_self = '';     // the current site's host, reported as "self"
$wpda_cur_blog = 0;
$wpda_host = function (string $url) use (&$wpda_self): string {
    $url = trim(html_entity_decode($url, ENT_QUOTES | ENT_HTML5));
    if (str_starts_with($url, '//')) {
        $url = 'https:' . $url;
    }
    $host = strtolower((string) parse_url($url, PHP_URL_HOST));

    return $host === '' || $host === $wpda_self ? 'self' : $host;
};
$wpda_scan = function (string $t, bool $encoded, int $depth = 0) use (&$wpda_scan, $wpda_host): array {
    $found = [];
    $add = function (string $kind, string $value) use (&$found, $encoded) {
        $found[$kind . "\0" . $value] = [$kind, $value, $encoded];
    };
    if (preg_match_all('#<script\b([^>]*)>(.*?)(?:</script\s*>|$)#is', $t, $m, PREG_SET_ORDER)) {
        foreach ($m as $s) {
            if (preg_match('#\btype\s*=\s*["\']?[^"\'\s>]*(json|template|text/x-)#i', $s[1])) {
                continue; // data, not code
            }
            if (preg_match('#\bsrc\s*=\s*["\']?([^"\'\s>]+)#i', $s[1], $src)) {
                $add('script-src', $wpda_host($src[1]));
            } else {
                $add('script-inline', mb_substr(trim(preg_replace('/\s+/', ' ', $s[2])), 0, 4000));
            }
        }
    }
    if (preg_match_all('#<iframe\b[^>]*\bsrc\s*=\s*["\']?([^"\'\s>]+)#i', $t, $m)) {
        foreach ($m[1] as $src) {
            $add('iframe', $wpda_host($src));
        }
    }
    if (preg_match_all('#javascript\s*:[^"\'<>]{0,80}#i', $t, $m)) {
        foreach ($m[0] as $v) {
            $add('js-url', trim($v));
        }
    }
    if (preg_match_all('#data\s*:\s*text/(?:html|javascript)[^"\'\s<>]{0,80}#i', $t, $m)) {
        foreach ($m[0] as $v) {
            $add('data-url', $v);
        }
    }
    if (preg_match_all('#\b(?:eval|base64_decode|gzinflate|gzuncompress|str_rot13|shell_exec|passthru)\s*\([^)]{0,60}#i', $t, $m)) {
        foreach ($m[0] as $v) {
            $add('php-call', $v);
        }
    }
    if (preg_match_all('#<(div|span|p)\b[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|(?:left|top)\s*:\s*-\d{3,}px)[^>]*>(?:(?!</\1>).){0,2000}?<a\b[^>]*href\s*=\s*["\']?([^"\'\s>]+)#is', $t, $m)) {
        foreach ($m[2] as $href) {
            $add('hidden-link', $wpda_host($href));
        }
    }
    if ($depth === 0) {
        if (preg_match_all('#(?:PHNjcmlwd|PGlmcmFtZ)[A-Za-z0-9+/=]{0,4000}#', $t, $m)) {
            foreach ($m[0] as $b) {
                $found += $wpda_scan((string) base64_decode($b), true, 1);
            }
        }
        $n = html_entity_decode($t, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        if (stripos($n, '%3c') !== false) {
            $n = urldecode($n);
        }
        if ($n !== $t) {
            foreach ($wpda_scan($n, true, 1) as $k => $f) {
                $found[$k] ??= $f;
            }
        }
    }

    return $found;
};

// One entry per distinct kind + value: how often, and the first places.
$wpda_hits = [];
$wpda['content_truncated'] = false;
$wpda_record = function (string $table, int $id, string $field, string $key, ?string $text) use (&$wpda, &$wpda_hits, &$wpda_cur_blog, $wpda_scan, $wpda_max) {
    if ($text === null || $text === '') {
        return;
    }
    foreach ($wpda_scan($text, false) as [$kind, $value, $encoded]) {
        $hash = substr(hash('sha256', $kind . "\0" . $value), 0, 16);
        if (! isset($wpda_hits[$hash])) {
            if (count($wpda_hits) >= $wpda_max) {
                $wpda['content_truncated'] = true;

                continue;
            }
            $wpda_hits[$hash] = ['kind' => $kind, 'hash' => $hash, 'snippet' => mb_substr($value, 0, 160), 'encoded' => $encoded, 'count' => 0, 'at' => []];
        }
        $wpda_hits[$hash]['count']++;
        if (count($wpda_hits[$hash]['at']) < 5) {
            $wpda_hits[$hash]['at'][] = ['blog' => $wpda_cur_blog, 'table' => $table, 'id' => $id, 'field' => $field, 'key' => $key];
        }
    }
};
$wpda_patterns = ['<script', '&lt;script', '%3cscript', '<iframe', '&lt;iframe', 'javascript:', 'data:text/', 'PHNjcmlwd', 'PGlmcmFtZ', 'eval(', 'base64_decode(', 'gzinflate(', 'gzuncompress(', 'str_rot13(', 'shell_exec(', 'passthru(', 'display:none', 'display: none', 'visibility:hidden', 'visibility: hidden'];
$wpda_like = function (array $cols) use ($wpdb, $wpda_patterns): string {
    $or = [];
    foreach ($cols as $col) {
        foreach ($wpda_patterns as $p) {
            $or[] = $wpdb->prepare("{$col} LIKE %s", '%' . $wpdb->esc_like($p) . '%');
        }
    }

    return '(' . implode(' OR ', $or) . ')';
};
$wpda_query = function (string $sql) use ($wpdb, &$wpda, $wpda_rows, &$wpda_errors): array {
    $rows = $wpdb->get_results($sql . " LIMIT {$wpda_rows}");
    if ($wpdb->last_error) {
        $wpda_errors[] = 'content query: ' . $wpdb->last_error;
    }
    if (count($rows) >= $wpda_rows) {
        $wpda['content_truncated'] = true;
    }

    return $rows;
};

$wpda_each(function (int $blog) use ($wpdb, $wpda_query, $wpda_like, $wpda_record, &$wpda_self, &$wpda_cur_blog) {
    $wpda_cur_blog = $blog;
    $wpda_self = strtolower((string) parse_url(home_url(), PHP_URL_HOST));
    foreach ($wpda_query("SELECT ID, post_title, post_content, post_excerpt FROM {$wpdb->posts} WHERE post_type <> 'revision' AND " . $wpda_like(['post_title', 'post_content', 'post_excerpt'])) as $r) {
        $wpda_record('posts', (int) $r->ID, 'post_title', '', $r->post_title);
        $wpda_record('posts', (int) $r->ID, 'post_content', '', $r->post_content);
        $wpda_record('posts', (int) $r->ID, 'post_excerpt', '', $r->post_excerpt);
    }
    // _oembed_* is WordPress's cache of embed HTML for URLs already in content.
    foreach ($wpda_query("SELECT post_id, meta_key, meta_value FROM {$wpdb->postmeta} WHERE meta_key NOT LIKE '\\_oembed\\_%' AND " . $wpda_like(['meta_value'])) as $r) {
        $wpda_record('postmeta', (int) $r->post_id, 'meta_value', (string) $r->meta_key, $r->meta_value);
    }
    foreach ($wpda_query("SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name NOT LIKE '\\_transient\\_%' AND option_name NOT LIKE '\\_site\\_transient\\_%' AND " . $wpda_like(['option_value'])) as $r) {
        $wpda_record('options', 0, 'option_value', (string) $r->option_name, $r->option_value);
    }
    foreach ($wpda_query("SELECT t.term_id, t.name, tt.description FROM {$wpdb->terms} t JOIN {$wpdb->term_taxonomy} tt ON tt.term_id = t.term_id WHERE " . $wpda_like(['t.name', 'tt.description'])) as $r) {
        $wpda_record('terms', (int) $r->term_id, 'name', '', $r->name);
        $wpda_record('terms', (int) $r->term_id, 'description', '', $r->description);
    }
    foreach ($wpda_query("SELECT term_id, meta_key, meta_value FROM {$wpdb->termmeta} WHERE " . $wpda_like(['meta_value'])) as $r) {
        $wpda_record('termmeta', (int) $r->term_id, 'meta_value', (string) $r->meta_key, $r->meta_value);
    }
    foreach ($wpda_query("SELECT comment_ID, comment_content FROM {$wpdb->comments} WHERE comment_approved = '1' AND " . $wpda_like(['comment_content'])) as $r) {
        $wpda_record('comments', (int) $r->comment_ID, 'comment_content', '', $r->comment_content);
    }
});
$wpda['content'] = array_values($wpda_hits);

// Files: executable files under uploads, and what sits in the plugin,
// mu-plugin and drop-in places (the Go side compares those with the repo).
$wpda['files'] = ['uploads_php' => [], 'uploads_truncated' => false];
$wpda_up = wp_upload_dir(null, false);
$wpda_base = (string) ($wpda_up['basedir'] ?? '');
if ($wpda_base !== '' && is_dir($wpda_base)) {
    try {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($wpda_base, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if (! $f->isFile() || ! preg_match('/\.(php\d?|phtml|phar|pht|phps)$/i', $f->getFilename())) {
                continue;
            }
            if (count($wpda['files']['uploads_php']) >= $wpda_max) {
                $wpda['files']['uploads_truncated'] = true;
                break;
            }
            $size = (int) $f->getSize();
            $body = $size <= 1048576 ? (string) file_get_contents($f->getPathname()) : null;
            $wpda['files']['uploads_php'][] = [
                'path' => substr($f->getPathname(), strlen($wpda_base) + 1),
                'size' => $size,
                'mtime' => (int) $f->getMTime(),
                'sha256' => $body !== null ? hash('sha256', $body) : '',
                // empty, or a "Silence is golden" directory guard: harmless
                'silence' => $size === 0 || ($size <= 200 && stripos((string) $body, 'silence is golden') !== false),
            ];
        }
    } catch (Throwable $e) {
        $wpda_errors[] = 'uploads scan: ' . $e->getMessage();
    }
}
$wpda_ls = function (string $dir, bool $phpOnly = false): array {
    $out = [];
    foreach (is_dir($dir) ? (scandir($dir) ?: []) : [] as $name) {
        if ($name[0] === '.' || $name === 'index.php') {
            continue;
        }
        if ($phpOnly ? (is_file("$dir/$name") && str_ends_with($name, '.php')) : true) {
            $out[] = $name;
        }
    }

    return $out;
};
$wpda['files']['plugins'] = $wpda_ls(WP_PLUGIN_DIR);
$wpda['files']['mu_plugins'] = $wpda_ls(WPMU_PLUGIN_DIR);
$wpda['files']['dropins'] = $wpda_ls(WP_CONTENT_DIR, true);

// Checksums against wordpress.org: core, and the wp.org plugins (premium
// ones have none and are only counted as skipped).
$wpda['checksums'] = ['core' => [], 'plugins' => [], 'plugins_skipped' => 0];
try {
    $r = WP_CLI::runcommand('core verify-checksums', ['return' => 'all', 'exit_error' => false, 'launch' => false]);
    foreach (preg_split('/\R/', $r->stdout . "\n" . $r->stderr) as $line) {
        if (stripos($line, 'Warning:') !== false || stripos($line, 'Error:') !== false) {
            $wpda['checksums']['core'][] = trim($line);
        }
    }
} catch (Throwable $e) {
    $wpda_errors[] = 'core verify-checksums: ' . $e->getMessage();
}
try {
    $r = WP_CLI::runcommand('plugin verify-checksums --all --format=json', ['return' => 'all', 'exit_error' => false, 'launch' => false]);
    if (preg_match('/\[.*\]/s', $r->stdout, $m)) {
        foreach ((array) json_decode($m[0], true) as $row) {
            $wpda['checksums']['plugins'][] = [
                'plugin' => (string) ($row['plugin_name'] ?? ''),
                'file' => (string) ($row['file'] ?? ''),
                'message' => (string) ($row['message'] ?? ''),
            ];
        }
    }
    $wpda['checksums']['plugins_skipped'] = preg_match_all('/Could not retrieve the checksums/i', $r->stderr);
} catch (Throwable $e) {
    $wpda_errors[] = 'plugin verify-checksums: ' . $e->getMessage();
}

$wpda['errors'] = $wpda_errors;
echo "\nWPDA-BEGIN\n" . wp_json_encode($wpda, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\nWPDA-END\n";
