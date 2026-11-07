<?php

/*
 * wp-data-audit collector, piped to `wp eval-file - --skip-plugins
 * --skip-themes` (so only core, mu-plugins and drop-ins run beside it).
 * wp-data-audit puts $wpda_public_roles above this file. Read-only: it
 * changes nothing on the site and prints facts as JSON between WPDA-BEGIN and
 * WPDA-END. Judging them is the Go side's job, so rules change without
 * touching sites.
 *
 * Personal data is kept to what an audit needs. Public roles are the ones
 * anyone can get on a site: `customer` where WooCommerce runs, plus what the
 * repo declares per site (host or blog id => roles). Users holding only
 * public roles are counted; everyone else (and anyone with extra capabilities
 * or application passwords) is listed. Content is never printed, only what
 * matched, cut short.
 */

global $wpdb;

// The lowest CPU priority: the site's visitors come first. (The database
// server's own work can't be lowered from here; the queries below keep it
// small: paged, each page forgotten before the next.)
function_exists('proc_nice') && @proc_nice(19);

// Each page of rows is handed to $each, then dropped (wpdb keeps a copy of
// the last result otherwise), so memory holds one page whatever the table's
// size. Keyset paging by a unique, indexed $key: each page continues where
// the last ended, so the table is read once in all.
$wpda_pages = function (string $sql, string $key, int $page, callable $each, int $max = PHP_INT_MAX) use ($wpdb): ?string {
    $last = 0;
    $seen = 0;
    while ($seen < $max) {
        $rows = $wpdb->get_results("{$sql} AND {$key} > {$last} ORDER BY {$key} LIMIT {$page}");
        if ($wpdb->last_error) {
            return $wpdb->last_error;
        }
        foreach ($rows as $r) {
            $each($r);
            $last = (int) $r->wpda_k;
        }
        $seen += count($rows);
        $wpdb->flush();
        if (count($rows) < $page) {
            return null;
        }
    }

    return 'truncated';
};

$wpda_public_roles = isset($wpda_public_roles) && is_array($wpda_public_roles) ? $wpda_public_roles : [];
$wpda_public = function (int $blog) use ($wpda_public_roles): array {
    $host = strtolower((string) parse_url(home_url(), PHP_URL_HOST));
    $roles = array_merge($wpda_public_roles[$host] ?? [], $wpda_public_roles[(string) $blog] ?? []);
    if (get_option('woocommerce_version')) {
        $roles[] = 'customer';
    }
    // Open registration: anyone gets the default role, so it's public here,
    // but only while it can do no more than read. A default role with more is
    // the registration check's urgent flag, and its holders stay listed.
    $open = is_multisite()
        ? $blog === (int) get_main_site_id() && in_array(get_site_option('registration'), ['user', 'all'], true)
        : (bool) get_option('users_can_register');
    $default = (string) get_option('default_role');
    $role = $open && $default !== '' ? get_role($default) : null;
    if ($role && ! array_diff(array_keys(array_filter($role->capabilities)), ['read', 'level_0'])) {
        $roles[] = $default;
    }

    return $roles;
};
$wpda_errors = [];
$wpda_rows = 20000;   // candidate rows per content table (read 100 at a time); reaching it marks the scan truncated
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
    'woocommerce' => get_option('woocommerce_version') !== false, // plugins are skipped: the option, not the class
    'multisite' => is_multisite(),
    'timings' => [],
];
// Each section's seconds, for -v; $wpda_skip (from the Go side) names the
// sections not to run: content, retention, checksums.
$wpda_skip ??= [];
$wpda_t = microtime(true);
$wpda_timed = function (string $section) use (&$wpda, &$wpda_t) {
    $now = microtime(true);
    $wpda['timings'][$section] = round($now - $wpda_t, 2);
    $wpda_t = $now;
};

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
$wpda_public_caps = [];
$wpda_each(function (int $blog) use ($wpdb, $wpda_tag, $wpda_public, $wpda_pages, &$wpda_errors, &$wpda_user_roles, &$wpda_privileged, &$wpda_detail, &$wpda_counts, &$wpda_public_caps) {
    $site_roles = wp_roles();
    $public = $wpda_public($blog);
    // Role definitions are data too: a public role that grants more than
    // reading makes all its users privileged without listing them.
    foreach ($public as $r) {
        $role = $site_roles->get_role($r);
        $wpda_public_caps[$wpda_tag($blog, $r)] = $role ? array_keys(array_filter($role->capabilities)) : [];
    }
    $capkey = $wpdb->get_blog_prefix() . 'capabilities';
    // A shop's customers can be hundreds of thousands of rows: paged.
    $sql = $wpdb->prepare("SELECT umeta_id AS wpda_k, user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s", $capkey);
    $err = $wpda_pages($sql, 'umeta_id', 5000, function ($row) use ($blog, $site_roles, $public, $wpda_tag, &$wpda_user_roles, &$wpda_privileged, &$wpda_detail, &$wpda_counts) {
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
    });
    if ($err !== null) {
        $wpda_errors[] = "users of blog {$blog}: {$err}";
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
$wpda['public_role_caps'] = (object) $wpda_public_caps;

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
    // WordPress keeps no last login; WooCommerce and login-tracking plugins
    // do, under these keys (a timestamp or a date).
    $last_active = 0;
    foreach (['wc_last_active', 'last_login', '_last_login', 'wp-last-login', 'last_activity'] as $key) {
        $v = get_user_meta($id, $key, true);
        $t = is_numeric($v) ? (int) $v : (is_string($v) && $v !== '' ? (int) strtotime($v) : 0);
        $last_active = max($last_active, $t > 0 && $t <= time() + 86400 ? $t : 0);
    }
    // The hash's scheme, never the hash: since WordPress 6.8 a password login
    // rehashes phpass ($P$) to $wp$, so phpass means no password login since.
    $pass = (string) $u->user_pass;
    $hash = match (true) {
        str_starts_with($pass, '$wp$') => 'wp-bcrypt',
        str_starts_with($pass, '$P$') || str_starts_with($pass, '$H$') => 'phpass',
        (bool) preg_match('/^[0-9a-f]{32}$/', $pass) => 'md5',
        str_starts_with($pass, '$2y$') || str_starts_with($pass, '$argon') => 'bcrypt',
        default => 'other',
    };
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
        'last_active' => $last_active,
        'hash' => $hash,
    ];
}

$wpda_timed('accounts');

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

// Per site: active plugins, scheduled (cron) hook names, and a hash of each
// sensitive option (never its value: gateway settings hold API keys). The Go
// side compares them with the last audit. Network-active plugins are
// "network"'s.
$wpda['active_plugins'] = [];
// Installed: the plugin folder's entries (folders, and single-file plugins),
// by name only, as plugins aren't loaded.
$wpda['installed_plugins'] = [];
foreach (defined('WP_PLUGIN_DIR') && is_dir(WP_PLUGIN_DIR) ? (scandir(WP_PLUGIN_DIR) ?: []) : [] as $entry) {
    if ($entry[0] !== '.' && (is_dir(WP_PLUGIN_DIR . "/{$entry}") || str_ends_with($entry, '.php')) && $entry !== 'index.php') {
        $wpda['installed_plugins'][] = $entry;
    }
}
$wpda['cron'] = [];
$wpda['sensitive'] = [];
if (is_multisite()) {
    $wpda['active_plugins']['network'] = array_map('strval', array_keys((array) get_site_option('active_sitewide_plugins', [])));
}
$wpda_each(function (int $blog) use ($wpdb, &$wpda, $wpda_tag) {
    $wpda['active_plugins'][(string) $blog] = array_values(array_map('strval', (array) get_option('active_plugins', [])));
    $hooks = [];
    foreach ((array) (function_exists('_get_cron_array') ? _get_cron_array() : []) as $events) {
        foreach (array_keys((array) $events) as $hook) {
            $hooks[(string) $hook] = true;
        }
    }
    ksort($hooks);
    $wpda['cron'][(string) $blog] = array_keys($hooks);
    // Theme, upload paths, role definitions, SMTP plugins' settings, and each
    // payment gateway's settings (WooCommerce's gateway order names them).
    $names = ['template', 'stylesheet', 'upload_path', 'upload_url_path', $wpdb->prefix . 'user_roles',
        'wp_mail_smtp', 'postman_options', 'post_smtp_options', 'swpsmtp_options', 'easy_wp_smtp', 'fluentmail-settings', 'woocommerce_gateway_order'];
    foreach (array_keys((array) get_option('woocommerce_gateway_order', [])) as $gateway) {
        if (preg_match('/^[a-z0-9_-]{1,60}$/i', (string) $gateway)) {
            $names[] = "woocommerce_{$gateway}_settings";
        }
    }
    $in = implode(', ', array_fill(0, count($names), '%s'));
    foreach ($wpdb->get_results($wpdb->prepare("SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name IN ({$in})", $names)) as $o) {
        $name = $o->option_name === $wpdb->prefix . 'user_roles' ? 'user_roles' : (string) $o->option_name;
        $wpda['sensitive'][$wpda_tag($blog, $name)] = substr(hash('sha256', (string) $o->option_value), 0, 16);
    }
    $wpdb->flush();
});
$wpda['active_plugins'] = (object) $wpda['active_plugins'];
$wpda['cron'] = (object) $wpda['cron'];
$wpda['sensitive'] = (object) $wpda['sensitive'];
$wpda_timed('plugins');

// How long personal data is kept: per Gravity Forms form its entry count,
// oldest entry and retention setting; per WooCommerce shop its order count,
// oldest order and the anonymise/delete settings. Counts and dates only.
$wpda['retention'] = ['forms' => [], 'woo' => []];
empty($wpda_skip['retention']) && $wpda_each(function (int $blog) use ($wpdb, &$wpda) {
    $has = fn (string $t) => (bool) $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($t)));
    $p = $wpdb->prefix;
    if ($has("{$p}gf_entry") && $has("{$p}gf_form")) {
        $meta = [];
        if ($has("{$p}gf_form_meta")) {
            foreach ($wpdb->get_results("SELECT form_id, display_meta FROM {$p}gf_form_meta") as $m) {
                $d = json_decode((string) $m->display_meta, true);
                $meta[(int) $m->form_id] = $d['personalData']['retention'] ?? [];
            }
        }
        $sql = "SELECT f.id, f.title, COUNT(e.id) AS n, MIN(e.date_created) AS oldest FROM {$p}gf_form f
            JOIN {$p}gf_entry e ON e.form_id = f.id AND e.status = 'active' GROUP BY f.id, f.title";
        foreach ($wpdb->get_results($sql) as $f) {
            $r = $meta[(int) $f->id] ?? [];
            $wpda['retention']['forms'][] = [
                'blog' => $blog,
                'form_id' => (int) $f->id,
                'title' => substr((string) $f->title, 0, 120),
                'entries' => (int) $f->n,
                'oldest' => (string) $f->oldest,
                'policy' => (string) ($r['policy'] ?? 'retain'),
                'days' => (int) ($r['retain_entries_days'] ?? 0),
            ];
        }
    }
    if (get_option('woocommerce_version') === false) {
        return;
    }
    $hpos = get_option('woocommerce_custom_orders_table_enabled') === 'yes' && $has("{$p}wc_orders");
    $row = $hpos
        ? $wpdb->get_row("SELECT COUNT(*) AS n, MIN(date_created_gmt) AS oldest FROM {$p}wc_orders WHERE type = 'shop_order'")
        : $wpdb->get_row("SELECT COUNT(*) AS n, MIN(post_date_gmt) AS oldest FROM {$wpdb->posts} WHERE post_type = 'shop_order'");
    $settings = [];
    foreach (['delete_inactive_accounts', 'trash_pending_orders', 'trash_failed_orders', 'trash_cancelled_orders', 'anonymize_refunded_orders', 'anonymize_completed_orders'] as $k) {
        $v = get_option("woocommerce_{$k}");
        $settings[$k] = is_array($v) && ! empty($v['number']) ? (int) $v['number'] . ' ' . (string) ($v['unit'] ?? '') : '';
    }
    $wpda['retention']['woo'][] = [
        'blog' => $blog,
        'orders' => (int) ($row->n ?? 0),
        'oldest' => (string) ($row->oldest ?? ''),
        'settings' => $settings,
    ];
});
$wpda_timed('retention');

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
// A regex that hits PCRE's backtrack limit returns false: counted, so a scan
// that silently missed something says so.
$wpda_pcre = 0;
$wpda_pm = function (string $re, string $t, &$m = null, int $flags = PREG_PATTERN_ORDER) use (&$wpda_pcre): int {
    $r = preg_match_all($re, $t, $m, $flags);
    if ($r === false) {
        $wpda_pcre++;

        return 0;
    }

    return $r;
};
$wpda_scan = function (string $t, bool $encoded, int $depth = 0) use (&$wpda_scan, $wpda_host, $wpda_pm): array {
    $found = [];
    $add = function (string $kind, string $value) use (&$found, $encoded) {
        $found[$kind . "\0" . $value] = [$kind, $value, $encoded];
    };
    if ($wpda_pm('#<script\b([^>]*)>(.*?)(?:</script\s*>|$)#is', $t, $m, PREG_SET_ORDER)) {
        foreach ($m as $s) {
            // Browsers run a script without a type, a module, or a JavaScript MIME
            // type (text/x-javascript included); anything else is data.
            if (preg_match('#\btype\s*=\s*["\']?([^"\'\s>;]*)#i', $s[1], $type) && $type[1] !== ''
                && ! preg_match('#^(module|(text|application)/(x-)?(java|ecma|j|live)script[0-9.]*)$#i', $type[1])) {
                continue;
            }
            if (preg_match('#\bsrc\s*=\s*["\']?([^"\'\s>]+)#i', $s[1], $src)) {
                $add('script-src', $wpda_host($src[1]));
            } else {
                $add('script-inline', mb_substr(trim(preg_replace('/\s+/', ' ', $s[2])), 0, 4000));
            }
        }
    }
    if ($wpda_pm('#<iframe\b[^>]*\bsrc\s*=\s*["\']?([^"\'\s>]+)#i', $t, $m)) {
        foreach ($m[1] as $src) {
            $add('iframe', $wpda_host($src));
        }
    }
    if ($wpda_pm('#javascript\s*:[^"\'<>]{0,80}#i', $t, $m)) {
        foreach ($m[0] as $v) {
            $add('js-url', trim($v));
        }
    }
    if ($wpda_pm('#data\s*:\s*text/(?:html|javascript)[^"\'\s<>]{0,80}#i', $t, $m)) {
        foreach ($m[0] as $v) {
            $add('data-url', $v);
        }
    }
    if ($wpda_pm('#\b(?:eval|base64_decode|gzinflate|gzuncompress|str_rot13|shell_exec|passthru)\s*\([^)]{0,60}#i', $t, $m)) {
        foreach ($m[0] as $v) {
            $add('php-call', $v);
        }
    }
    if ($wpda_pm('#<(div|span|p)\b[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|(?:left|top)\s*:\s*-\d{3,}px)[^>]*>(?:(?!</\1>).){0,2000}?<a\b[^>]*href\s*=\s*["\']?([^"\'\s>]+)#is', $t, $m)) {
        foreach ($m[2] as $href) {
            $add('hidden-link', $wpda_host($href));
        }
    }
    if ($depth === 0) {
        if ($wpda_pm('#(?:PHNjcmlwd|PGlmcmFtZ)[A-Za-z0-9+/=]{0,4000}#', $t, $m)) {
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
// Candidate rows are found in SQL and scanned exactly in PHP. One REGEXP over
// the lowercased columns is several times faster than a case-insensitive LIKE
// per pattern and column; the LIKEs stay as the fallback for a database that
// rejects the regex.
$wpda_regexp = function (array $cols) use ($wpdb, $wpda_patterns): string {
    $alts = implode('|', array_map(fn ($p) => preg_quote(strtolower($p), '/'), $wpda_patterns));

    return $wpdb->prepare('LOWER(CONCAT_WS(\' \', ' . implode(', ', $cols) . ')) REGEXP %s', $alts);
};
$wpda_like = function (array $cols) use ($wpdb, $wpda_patterns): string {
    $or = [];
    foreach ($cols as $col) {
        foreach ($wpda_patterns as $p) {
            $or[] = $wpdb->prepare("{$col} LIKE %s", '%' . $wpdb->esc_like($p) . '%');
        }
    }

    return '(' . implode(' OR ', $or) . ')';
};
// Candidate rows, streamed: an unbuffered query hands PHP one row at a time
// from one scan of the table (meta and post values can be megabytes each),
// up to $wpda_rows per table. Safe because matching a row runs no query.
// Without mysqli (a drop-in database driver) they're paged instead.
$wpda_stream = function (string $sql, string $key, callable $each, int $max) use ($wpdb, $wpda_pages): ?string {
    if (! ($wpdb->dbh instanceof mysqli)) {
        return $wpda_pages($sql, $key, 100, $each, $max);
    }
    $sql = $wpdb->remove_placeholder_escape($sql) . ' LIMIT ' . ($max + 1);
    try {
        $res = mysqli_query($wpdb->dbh, $sql, MYSQLI_USE_RESULT);
    } catch (Throwable $e) {
        return $e->getMessage();
    }
    if ($res === false) {
        return mysqli_error($wpdb->dbh);
    }
    $n = 0;
    while ($r = mysqli_fetch_object($res)) {
        if (++$n > $max) {
            break;
        }
        $each($r);
    }
    mysqli_free_result($res); // reads off any rows left, freeing the connection

    return $n > $max ? 'truncated' : null;
};
$wpda_like_only = false;
$wpda_query = function (string $sql, string $key, array $cols, callable $each) use (&$wpda, $wpda_rows, &$wpda_errors, $wpda_regexp, $wpda_like, $wpda_stream, &$wpda_like_only) {
    $err = $wpda_like_only ? 'regexp' : $wpda_stream($sql . $wpda_regexp($cols), $key, $each, $wpda_rows);
    if ($err !== null && $err !== 'truncated' && ! $wpda_like_only) {
        $wpda_like_only = true; // the REGEXP failed before any row: nothing handed over twice
    }
    if ($wpda_like_only) {
        $err = $wpda_stream($sql . $wpda_like($cols), $key, $each, $wpda_rows);
    }
    if ($err === 'truncated') {
        $wpda['content_truncated'] = true;
    } elseif ($err !== null) {
        $wpda_errors[] = 'content query: ' . $err;
    }
};

empty($wpda_skip['content']) && $wpda_each(function (int $blog) use ($wpdb, $wpda_query, $wpda_record, &$wpda_self, &$wpda_cur_blog) {
    $wpda_cur_blog = $blog;
    $wpda_self = strtolower((string) parse_url(home_url(), PHP_URL_HOST));
    $wpda_query("SELECT ID AS wpda_k, post_title, post_content, post_excerpt FROM {$wpdb->posts} WHERE post_type <> 'revision' AND ", 'ID', ['post_title', 'post_content', 'post_excerpt'], function ($r) use ($wpda_record) {
        $wpda_record('posts', (int) $r->wpda_k, 'post_title', '', $r->post_title);
        $wpda_record('posts', (int) $r->wpda_k, 'post_content', '', $r->post_content);
        $wpda_record('posts', (int) $r->wpda_k, 'post_excerpt', '', $r->post_excerpt);
    });
    // _oembed_* is WordPress's cache of embed HTML for URLs already in content.
    $wpda_query("SELECT meta_id AS wpda_k, post_id, meta_key, meta_value FROM {$wpdb->postmeta} WHERE meta_key NOT LIKE '\\_oembed\\_%' AND ", 'meta_id', ['meta_value'], function ($r) use ($wpda_record) {
        $wpda_record('postmeta', (int) $r->post_id, 'meta_value', (string) $r->meta_key, $r->meta_value);
    });
    $wpda_query("SELECT option_id AS wpda_k, option_name, option_value FROM {$wpdb->options} WHERE option_name NOT LIKE '\\_transient\\_%' AND option_name NOT LIKE '\\_site\\_transient\\_%' AND ", 'option_id', ['option_value'], function ($r) use ($wpda_record) {
        $wpda_record('options', 0, 'option_value', (string) $r->option_name, $r->option_value);
    });
    $wpda_query("SELECT tt.term_taxonomy_id AS wpda_k, t.term_id, t.name, tt.description FROM {$wpdb->terms} t JOIN {$wpdb->term_taxonomy} tt ON tt.term_id = t.term_id WHERE ", 'tt.term_taxonomy_id', ['t.name', 'tt.description'], function ($r) use ($wpda_record) {
        $wpda_record('terms', (int) $r->term_id, 'name', '', $r->name);
        $wpda_record('terms', (int) $r->term_id, 'description', '', $r->description);
    });
    $wpda_query("SELECT meta_id AS wpda_k, term_id, meta_key, meta_value FROM {$wpdb->termmeta} WHERE ", 'meta_id', ['meta_value'], function ($r) use ($wpda_record) {
        $wpda_record('termmeta', (int) $r->term_id, 'meta_value', (string) $r->meta_key, $r->meta_value);
    });
    $wpda_query("SELECT comment_ID AS wpda_k, comment_content FROM {$wpdb->comments} WHERE comment_approved = '1' AND ", 'comment_ID', ['comment_content'], function ($r) use ($wpda_record) {
        $wpda_record('comments', (int) $r->wpda_k, 'comment_content', '', $r->comment_content);
    });
});
$wpda['content'] = array_values($wpda_hits);
if ($wpda_pcre > 0) {
    $wpda_errors[] = "content scan: {$wpda_pcre} pattern(s) hit PCRE's backtrack limit, so those values weren't fully scanned";
}
$wpda_timed('content');

// Files are the hasher's (hasher.php), which runs without WordPress.

// Checksums against wordpress.org, for sites whose files can't be compared
// with a local install of the deployed commit: core, and the wp.org plugins
// (premium ones have none and are only counted as skipped).
$wpda['checksums'] = ['core' => [], 'plugins' => [], 'plugins_skipped' => 0, 'skipped' => ! empty($wpda_skip['checksums'])];
if (empty($wpda_skip['checksums'])) {
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
}
$wpda_timed('checksums');

$wpda['errors'] = $wpda_errors;
$wpda['peak_mb'] = round(memory_get_peak_usage(true) / 1048576, 1); // WordPress's own share included
echo "\nWPDA-BEGIN\n" . wp_json_encode($wpda, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\nWPDA-END\n";
