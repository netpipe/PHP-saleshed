<?php
declare(strict_types=1);
/*
 * SaleShed — encrypted virtual garage sales & farmers-market stalls
 * PHP 8.0+ with pdo_sqlite, sodium, gd, fileinfo (exif optional)
 * Single file. Data (DB + master key) auto-created in ./garage-data/
 * CLI: php garage.php purge   (for cron)
 */
const GS_DEBUG = true; // set back to false once fixed
const GS_DATA          = __DIR__ . '/garage-data'; // ideally move ABOVE webroot
const GS_TZ            = 'UTC';                    // e.g. 'Australia/Melbourne'
const GS_BASE          = '';                       // optional fixed base URL, e.g. 'https://example.com/garage.php'
const MAX_PHOTOS       = 8;
const MAX_PHOTO_BYTES  = 4194304;                  // 4 MB per photo
const MAX_LISTINGS     = 20;                       // active listings per identity
const MAX_COMMENTS     = 300;                      // per listing
const COMMENT_COOLDOWN = 20;                       // seconds between comments per IP
const SHORT_MAX_DAYS   = 4;
const WEEKLY_WEEKS     = 8;

/* ---------------- boot ---------------- */

function boot(): void {
    date_default_timezone_set(GS_TZ);
    foreach (['pdo_sqlite','sodium','gd','fileinfo'] as $ext) {
        if (!extension_loaded($ext)) { http_response_code(500); exit('Missing PHP extension: '.$ext); }
    }
    if (!is_dir(GS_DATA) && !@mkdir(GS_DATA, 0700, true) && !is_dir(GS_DATA)) {
        http_response_code(500); exit('Cannot create data directory: '.GS_DATA);
    }
    if (!is_file(GS_DATA.'/.htaccess')) {
        @file_put_contents(GS_DATA.'/.htaccess',
            "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n".
            "<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
    }
    if (!is_file(GS_DATA.'/index.html')) @file_put_contents(GS_DATA.'/index.html', '');
    @ini_set('memory_limit', '256M');
    db(); mk();
}

function db(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $pdo = new PDO('sqlite:'.GS_DATA.'/garage.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA foreign_keys=ON');
    $pdo->exec('PRAGMA secure_delete=ON');
    $pdo->exec('PRAGMA busy_timeout=5000');
    foreach ([
        'CREATE TABLE IF NOT EXISTS identities(
            id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL)',
        'CREATE TABLE IF NOT EXISTS listings(
            id INTEGER PRIMARY KEY,
            identity_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
            view_hash TEXT NOT NULL UNIQUE, remove_hash TEXT NOT NULL UNIQUE,
            view_enc BLOB NOT NULL, key_wrapped BLOB NOT NULL,
            title_enc BLOB NOT NULL, descr_enc BLOB NOT NULL,
            town_enc BLOB NOT NULL, town_hash TEXT NOT NULL, addr_enc BLOB NOT NULL,
            kind TEXT NOT NULL, private INTEGER NOT NULL DEFAULT 0, mode TEXT NOT NULL,
            start_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            weekly_len_min INTEGER, created_at INTEGER NOT NULL)',
        'CREATE INDEX IF NOT EXISTS idx_browse ON listings(private, expires_at, town_hash)',
        'CREATE TABLE IF NOT EXISTS photos(
            id INTEGER PRIMARY KEY,
            listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
            blob BLOB NOT NULL, thumb BLOB NOT NULL, created_at INTEGER NOT NULL)',
        'CREATE INDEX IF NOT EXISTS idx_photos ON photos(listing_id)',
        'CREATE TABLE IF NOT EXISTS comments(
            id INTEGER PRIMARY KEY,
            listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
            name_enc BLOB NOT NULL, body_enc BLOB NOT NULL, created_at INTEGER NOT NULL)',
        'CREATE INDEX IF NOT EXISTS idx_comments ON comments(listing_id)',
        'CREATE TABLE IF NOT EXISTS throttle(k TEXT PRIMARY KEY, last_at INTEGER NOT NULL)',
    ] as $sql) $pdo->exec($sql);
    return $pdo;
}

function q(string $sql, array $p = []): PDOStatement { $st = db()->prepare($sql); $st->execute($p); return $st; }
function row(string $sql, array $p = []): ?array { $r = q($sql, $p)->fetch(); return $r === false ? null : $r; }

/* ---------------- crypto ---------------- */

function mk(): string {
    static $k = null;
    if ($k === null) {
        $f = GS_DATA.'/master.key';
        if (!is_file($f)) { file_put_contents($f, random_bytes(32)); @chmod($f, 0600); }
        $k = (string)file_get_contents($f);
        if (strlen($k) !== 32) throw new RuntimeException('master.key is corrupt');
    }
    return $k;
}
function enc(string $plain, string $key): string {
    $n = random_bytes(24);
    return $n . sodium_crypto_secretbox($plain, $n, $key);
}
function dec(string $blob, string $key): string {
    if (strlen($blob) < 40) throw new RuntimeException('bad ciphertext');
    $p = sodium_crypto_secretbox_open(substr($blob, 24), substr($blob, 0, 24), $key);
    if ($p === false) throw new RuntimeException('decryption failed');
    return $p;
}
function listing_key(array $l): string { return dec($l['key_wrapped'], mk()); }
function town_hash(string $t): string { return hash_hmac('sha256', norm_town($t), mk()); }
function tok(int $n = 16): string { return rtrim(strtr(base64_encode(random_bytes($n)), '+/', '-_'), '='); }

/* ---------------- identity / CSRF ---------------- */

function is_https(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}
function current_identity(): ?array {
    $t = (string)($_COOKIE['gs_id'] ?? '');
    if (!preg_match('/^[A-Za-z0-9_-]{20,64}$/', $t)) return null;
    return row('SELECT * FROM identities WHERE token_hash=?', [hash('sha256', $t)]);
}
function ensure_identity(): array {
    $cur = current_identity();
    if ($cur) return $cur;
    $t = tok(24);
    q('INSERT INTO identities (token_hash, created_at) VALUES (?,?)', [hash('sha256', $t), time()]);
    $_COOKIE['gs_id'] = $t;
    setcookie('gs_id', $t, ['expires'=>time()+365*86400, 'path'=>'/', 'httponly'=>true, 'secure'=>is_https(), 'samesite'=>'Lax']);
    return ['id'=>(int)db()->lastInsertId(), 'token_hash'=>hash('sha256', $t), 'created_at'=>time()];
}
function owner_of(array $l): bool {
    $id = current_identity();
    return $id && (int)$l['identity_id'] === (int)$id['id'];
}
function csrf_token(): string { return hash_hmac('sha256', 'gs-csrf', (string)($_COOKIE['gs_id'] ?? '')); }
function csrf_check(): void {
    if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) {
        http_response_code(403);
        page('Forbidden', '<div class="card"><h2>Session check failed</h2><p>Go back, reload the page and try again.</p></div>');
        exit;
    }
}
function find_by_view(string $t): ?array {
    if (!preg_match('/^[A-Za-z0-9_-]{16,64}$/', $t)) return null;
    return row('SELECT * FROM listings WHERE view_hash=?', [hash('sha256', $t)]);
}

/* ---------------- misc helpers ---------------- */

function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8'); }
function go(string $u): void { header('Location: '.$u); exit; }
function tz(): DateTimeZone { static $z; return $z ??= new DateTimeZone(GS_TZ); }
function base_url(): string {
    if (GS_BASE !== '') return rtrim(GS_BASE, '/');
    return (is_https()?'https':'http').'://'.($_SERVER['HTTP_HOST'] ?? 'localhost').($_SERVER['SCRIPT_NAME'] ?? '/garage.php');
}
function ulen(string $s): int { return function_exists('mb_strlen') ? mb_strlen($s, 'UTF-8') : strlen($s); }
function norm_town(string $s): string {
    $s = trim((string)preg_replace('/\s+/u', ' ', $s));
    return function_exists('mb_strtolower') ? mb_strtolower($s, 'UTF-8') : strtolower($s);
}
function fmt_dt(int $t): string { return (new DateTimeImmutable("@$t"))->setTimezone(tz())->format('D j M Y, H:i'); }
function fmt_d(int $t): string  { return (new DateTimeImmutable("@$t"))->setTimezone(tz())->format('D j M Y'); }
function fmt_t(int $t): string  { return (new DateTimeImmutable("@$t"))->setTimezone(tz())->format('H:i'); }
function ago(int $t): string {
    $d = time() - $t;
    if ($d < 60) return 'just now';
    if ($d < 3600) return intdiv($d, 60).' min ago';
    if ($d < 86400) return intdiv($d, 3600).' h ago';
    return intdiv($d, 86400).' d ago';
}
function span_left(int $s): string {
    if ($s < 3600) return max(1, intdiv($s, 60)).' min';
    if ($s < 86400) return intdiv($s, 3600).' h '.intdiv($s % 3600, 60).' min';
    return intdiv($s, 86400).' d '.intdiv($s % 86400, 3600).' h';
}
function purge_expired(): int {
    $n = q('DELETE FROM listings WHERE expires_at<=?', [time()])->rowCount();
    q('DELETE FROM throttle WHERE last_at<?', [time() - 86400]);
    return $n;
}
function next_occurrence(array $l): ?array {
    $base = (new DateTimeImmutable('@'.$l['start_at']))->setTimezone(tz());
    $len = (int)$l['weekly_len_min'] * 60;
    $now = time();
    for ($k = 0; $k < WEEKLY_WEEKS; $k++) {
        $s = $base->modify("+$k weeks")->getTimestamp();
        $e = $s + $len;
        if ($e > $now) return [$s, $e];
    }
    return null;
}
function weekly_summary(array $l): string {
    $b = (new DateTimeImmutable('@'.$l['start_at']))->setTimezone(tz());
    return 'Every '.$b->format('l').' '.$b->format('H:i').'–'.$b->modify('+'.(int)$l['weekly_len_min'].' minutes')->format('H:i');
}

/* ---------------- photos ---------------- */

function uploaded_files(string $field): array {
    if (!isset($_FILES[$field])) return [];
    $f = $_FILES[$field]; $out = [];
    if (is_array($f['name'])) {
        foreach ($f['name'] as $i => $n) {
            $out[] = ['name'=>$n, 'tmp_name'=>$f['tmp_name'][$i], 'error'=>$f['error'][$i], 'size'=>$f['size'][$i]];
        }
    } else $out[] = $f;
    return array_values(array_filter($out, fn($x) => $x['error'] !== UPLOAD_ERR_NO_FILE));
}
function scale_max(GdImage $im, int $max): GdImage {
    $w = imagesx($im); $h = imagesy($im); $m = max($w, $h);
    if ($m <= $max) return $im;
    return imagescale($im, (int)round($w*$max/$m), (int)round($h*$max/$m), IMG_BICUBIC) ?: $im;
}
function jpeg_of(GdImage $im, int $quality): string {
    $w = imagesx($im); $h = imagesy($im);
    $c = @imagecreatetruecolor($w, $h);
    if (!$c) throw new RuntimeException('Server ran out of memory processing a photo. Try fewer or smaller photos.');
    imagealphablending($c, true);
    imagefill($c, 0, 0, imagecolorallocate($c, 255, 255, 255));
    imagecopy($c, $im, 0, 0, 0, 0, $w, $h); // dst_x, dst_y, src_x, src_y, src_w, src_h
    ob_start(); imagejpeg($c, null, $quality); $d = (string)ob_get_clean();
    imagedestroy($c);
    if ($d === '') throw new RuntimeException('Could not encode a photo.');
    return $d;
}
function store_photo(array $f, string $key, int $lid): void {
    if ($f['error'] !== UPLOAD_ERR_OK) throw new RuntimeException('A photo failed to upload (code '.$f['error'].'). Max '.(MAX_PHOTO_BYTES/1048576).' MB each.');
    if ($f['size'] > MAX_PHOTO_BYTES) throw new RuntimeException('A photo is too large (max '.(MAX_PHOTO_BYTES/1048576).' MB).');
    if (!is_uploaded_file($f['tmp_name'])) throw new RuntimeException('Bad upload.');
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']);
    if (!in_array($mime, ['image/jpeg','image/png','image/webp','image/gif'], true))
        throw new RuntimeException('Photos must be JPG, PNG, WebP or GIF.');
    $info = @getimagesize($f['tmp_name']);
    if (!$info || $info[0]*$info[1] > 40000000) throw new RuntimeException('A photo is unreadable or too many megapixels.');
    $im = @imagecreatefromstring((string)file_get_contents($f['tmp_name']));
    if (!$im) throw new RuntimeException('Could not decode a photo.');
    if ($mime === 'image/jpeg' && function_exists('exif_read_data')) {
        $ex = @exif_read_data($f['tmp_name']);
        $o = (int)($ex['Orientation'] ?? 1);
        if ($o === 3) $im = imagerotate($im, 180, 0);
        elseif ($o === 6) $im = imagerotate($im, -90, 0);
        elseif ($o === 8) $im = imagerotate($im, 90, 0);
    }
    // Re-encoding strips ALL metadata (EXIF/GPS) before encryption.
    $full  = jpeg_of(scale_max($im, 1600), 85);
    $thumb = jpeg_of(scale_max($im, 420), 72);
    imagedestroy($im);
    $st = db()->prepare('INSERT INTO photos (listing_id, blob, thumb, created_at) VALUES (?,?,?,?)');
    $st->bindValue(1, $lid, PDO::PARAM_INT);
    $st->bindValue(2, enc($full, $key), PDO::PARAM_LOB);
    $st->bindValue(3, enc($thumb, $key), PDO::PARAM_LOB);
    $st->bindValue(4, time(), PDO::PARAM_INT);
    $st->execute();
}

/* ---------------- actions ---------------- */

function act_home(): void {
    if (random_int(1, 20) === 1) purge_expired();
    $town = trim((string)($_GET['town'] ?? ''));
    $kind = (string)($_GET['kind'] ?? 'all');
    $sql = 'SELECT * FROM listings WHERE private=0 AND expires_at>?';
    $p = [time()];
    if ($town !== '') { $sql .= ' AND town_hash=?'; $p[] = town_hash($town); }
    if ($kind === 'garage' || $kind === 'market') { $sql .= ' AND kind=?'; $p[] = $kind; }
    $sql .= ' ORDER BY start_at ASC LIMIT 60';
    $rows = q($sql, $p)->fetchAll();

    $cards = ''; $towns = [];
    foreach ($rows as $r) {
        $k = listing_key($r);
        $ti = dec($r['title_enc'], $k); $tw = dec($r['town_enc'], $k);
        $towns[$tw] = true;
        $vt = dec($r['view_enc'], mk());
        $ph = row('SELECT id FROM photos WHERE listing_id=? ORDER BY id LIMIT 1', [$r['id']]);
        $cc = (int)row('SELECT COUNT(*) c FROM comments WHERE listing_id=?', [$r['id']])['c'];
        $img = $ph
            ? '<img class="thumb" loading="lazy" src="'.h('?a=img&s='.urlencode($vt).'&p='.$ph['id'].'&th=1').'" alt="">'
            : '<div class="thumb" style="display:flex;align-items:center;justify-content:center;font-size:36px">'.($r['kind']==='market'?'🥕':'🏷').'</div>';
        $badge = $r['kind']==='market' ? '<span class="badge market">Market</span>' : '<span class="badge">Garage sale</span>';
        $when = $r['mode']==='weekly' ? h(weekly_summary($r)) : 'until '.h(fmt_d((int)$r['expires_at']));
        $cards .= '<div class="card" style="padding:12px"><a href="'.h('?s='.urlencode($vt)).'" style="text-decoration:none;color:inherit">'
               . $img . '<h2 style="font-size:17px;margin:10px 0 6px">'.h($ti).'</h2></a>'.$badge
               . '<p class="muted" style="margin:6px 0 0">📍 '.h($tw).' · '.$when.' · 💬 '.$cc.'</p></div>';
    }
    if (!$cards) {
        $cards = '<div class="card"><p class="muted">No live listings'.($town!==''?' in “'.h($town).'”':'').' right now.'
               . ($town!==''?' Town search matches the exact town name as the seller entered it.':'')
               . ' <a href="?a=new">Create the first one →</a></p></div>';
    }
    $townList = '';
    foreach (array_keys($towns) as $tn) $townList .= '<option value="'.h($tn).'">';
    $townH = h($town);
    $gSel = $kind==='garage' ? 'selected' : '';
    $mSel = $kind==='market' ? 'selected' : '';
    $n = count($rows);
    $heading = $n.' live '.($n===1?'listing':'listings');
    page('Browse sales', <<<HTML
<div class="card">
  <h1>Virtual garage sales &amp; market stalls</h1>
  <p>Post photos, share one link, collect comments. Short sales run up to 4 days; market stalls repeat weekly for 2 months. Photos and text are stored encrypted, EXIF/GPS is stripped, and everything erases itself at expiry.</p>
  <p><a class="btn" href="?a=new">＋ Create a sale</a> <a class="btn ghost" href="?a=mine">My sales</a></p>
</div>
<form class="card" method="get" action="?">
  <div class="row">
    <label style="flex:2;margin:0">Find sales by town<input name="town" value="$townH" placeholder="e.g. Beechworth" list="towns"></label>
    <label style="flex:1;margin:0">Type<select name="kind"><option value="all">All</option><option value="garage" $gSel>Garage sales</option><option value="market" $mSel>Farmers markets</option></select></label>
    <button style="align-self:flex-end">Search</button>
  </div>
  <datalist id="towns">$townList</datalist>
  <p class="muted" style="margin:8px 0 0">Exact town match — town names are encrypted, so search uses a privacy-preserving index. Unlisted sales never appear here.</p>
</form>
<h2>$heading</h2>
<div class="grid">$cards</div>
HTML);
}

function act_new(): void { render_new([]); }

function render_new(array $v, string $err = ''): void {
    $get = fn(string $k, string $def): string => h((string)($v[$k] ?? $def));
    $mode = (string)($v['mode'] ?? 'short');
    $kind = (string)($v['kind'] ?? 'garage');
    $errHtml = $err !== '' ? '<div class="err">'.h($err).'</div>' : '';
    $gSel = $kind==='garage' ? 'selected' : '';
    $mSel = $kind==='market' ? 'selected' : '';
    $shChk = $mode==='short' ? 'checked' : '';
    $wkChk = $mode==='weekly' ? 'checked' : '';
    $privChk = !empty($v['private']) ? 'checked' : '';
    $daysSel = (int)($v['days'] ?? 2);
    $daysOpts = '';
    for ($i = 1; $i <= SHORT_MAX_DAYS; $i++) $daysOpts .= '<option value="'.$i.'"'.($i===$daysSel?' selected':'').'>'.$i.' day'.($i>1?'s':'').'</option>';
    $nextSat = (new DateTimeImmutable('next saturday'))->format('Y-m-d');
    $today = date('Y-m-d');
    page('Create a sale', <<<HTML
<h1>Create a sale or market stall</h1>
$errHtml
<form method="post" action="?a=create" enctype="multipart/form-data" class="card">
  <label>What is it?<select name="kind">
    <option value="garage" $gSel>🏷 Garage / yard sale</option>
    <option value="market" $mSel>🥕 Farmers market / recurring stall</option>
  </select></label>
  <label>Title<input name="title" required maxlength="120" value="{$get('title','')}" placeholder="Moving sale — tools, books, kids bikes"></label>
  <div class="row">
    <label style="flex:1">Town<input name="town" required maxlength="80" value="{$get('town','')}" placeholder="Beechworth"></label>
    <label style="flex:2">Street / location detail (optional)<input name="addr" maxlength="200" value="{$get('addr','')}" placeholder="12 Creek Rd — look for the balloons"></label>
  </div>
  <label>Description<textarea name="descr" rows="4" maxlength="4000" placeholder="What you're selling, prices, parking, rain plan…">{$get('descr','')}</textarea></label>
  <fieldset><legend>How long should it run?</legend>
    <label class="inline"><input type="radio" name="mode" value="short" onchange="modeSwap()" $shChk> Short sale — up to 4 days</label>
    <label class="inline" style="margin-left:16px"><input type="radio" name="mode" value="weekly" onchange="modeSwap()" $wkChk> Weekly — 8 weeks (2 months)</label>
    <div id="m-short">
      <div class="row">
        <label style="flex:1">Start date<input type="date" name="s_date" value="{$get('s_date',$today)}"></label>
        <label style="flex:1">Start time<input type="time" name="s_time" value="{$get('s_time','09:00')}"></label>
        <label style="flex:1">Days open<select name="days">$daysOpts</select></label>
      </div>
      <p class="muted">Photos, details and comments stay live for the chosen 1–4 days, then everything is erased.</p>
    </div>
    <div id="m-weekly">
      <div class="row">
        <label style="flex:1">First market day<input type="date" name="w_date" value="{$get('w_date',$nextSat)}"></label>
        <label style="flex:1">Opens<input type="time" name="w_time" value="{$get('w_time','08:00')}"></label>
        <label style="flex:1">Hours open<input type="number" name="w_hours" min="1" max="12" value="{$get('w_hours','4')}"></label>
      </div>
      <p class="muted">Repeats weekly on that day for 8 weeks. The page always shows the next market day.</p>
    </div>
  </fieldset>
  <label>Photos (up to 8 — JPG/PNG/WebP/GIF, max 4 MB each)<input type="file" name="photos[]" multiple accept="image/jpeg,image/png,image/webp,image/gif"></label>
  <p class="muted">Location metadata (EXIF/GPS) is stripped and images are re-encoded before encrypted storage. Re-select photos if the form shows an error.</p>
  <label class="inline"><input type="checkbox" name="private" value="1" $privChk> Unlisted — hide from town search; only people with the share link can see it</label>
  <p style="margin-top:16px"><button>Create &amp; get share link</button></p>
</form>
<p class="muted">No account needed: this browser gets a secret seller cookie. You can burn that identity (and everything it owns) any time from <a href="?a=mine">My sales</a>.</p>
HTML);
}

function act_create(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') go('?a=new');
    if (empty($_POST) && (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) {
        render_new([], 'The upload was larger than the server allows (post_max_size). Try fewer or smaller photos.');
        return;
    }
    $v = [
        'title'   => trim((string)($_POST['title'] ?? '')),
        'kind'    => (($_POST['kind'] ?? '') === 'market') ? 'market' : 'garage',
        'town'    => trim((string)($_POST['town'] ?? '')),
        'addr'    => trim((string)($_POST['addr'] ?? '')),
        'descr'   => trim((string)($_POST['descr'] ?? '')),
        'mode'    => (($_POST['mode'] ?? '') === 'weekly') ? 'weekly' : 'short',
        'private' => isset($_POST['private']) ? 1 : 0,
        's_date'  => (string)($_POST['s_date'] ?? ''), 's_time' => (string)($_POST['s_time'] ?? ''),
        'days'    => (string)($_POST['days'] ?? '2'),
        'w_date'  => (string)($_POST['w_date'] ?? ''), 'w_time' => (string)($_POST['w_time'] ?? ''),
        'w_hours' => (string)($_POST['w_hours'] ?? '4'),
    ];
    $err = '';
    if ($v['title'] === '' || ulen($v['title']) > 120) $err = 'Title is required (max 120 characters).';
    elseif ($v['town'] === '' || ulen($v['town']) > 80) $err = 'Town is required (max 80 characters).';
    elseif (ulen($v['addr']) > 200) $err = 'Location detail is too long (max 200).';
    elseif (ulen($v['descr']) > 4000) $err = 'Description is too long (max 4000).';
    $files = uploaded_files('photos');
    if (!$err && count($files) > MAX_PHOTOS) $err = 'Maximum '.MAX_PHOTOS.' photos.';

    $start = 0; $expires = 0; $len = null;
    $dateRe = '/^\d{4}-\d{2}-\d{2}$/'; $timeRe = '/^\d{2}:\d{2}$/';
    if (!$err) {
        if ($v['mode'] === 'short') {
            if (!preg_match($dateRe, $v['s_date']) || !preg_match($timeRe, $v['s_time'])) $err = 'Pick a valid start date and time.';
            else {
                $ts = strtotime($v['s_date'].' '.$v['s_time']);
                $days = (int)$v['days'];
                if ($ts === false) $err = 'Pick a valid start date and time.';
                elseif ($days < 1 || $days > SHORT_MAX_DAYS) $err = 'Short sales run 1–'.SHORT_MAX_DAYS.' days.';
                else {
                    $start = $ts; $expires = $start + $days*86400;
                    if ($expires <= time()) $err = 'That time window has already elapsed — pick a later start or more days.';
                }
            }
        } else {
            if (!preg_match($dateRe, $v['w_date']) || !preg_match($timeRe, $v['w_time'])) $err = 'Pick a valid first market day and time.';
            else {
                $ts = strtotime($v['w_date'].' '.$v['w_time']);
                $h = (int)$v['w_hours'];
                if ($ts === false) $err = 'Pick a valid first market day and time.';
                elseif ($h < 1 || $h > 12) $err = 'Market hours must be 1–12.';
                elseif ($ts < time() - 86400) $err = 'The first market day is in the past.';
                elseif ($ts > time() + 90*86400) $err = 'First market day is too far ahead (max 90 days).';
                else {
                    $start = $ts; $len = $h*60;
                    $expires = (new DateTimeImmutable("@$start"))->setTimezone(tz())
                        ->modify('+'.WEEKLY_WEEKS.' weeks')->getTimestamp() + $len*60;
                }
            }
        }
    }
    if ($err) { render_new($v, $err); return; }

    $id = ensure_identity();
    $cnt = (int)row('SELECT COUNT(*) c FROM listings WHERE identity_id=? AND expires_at>?', [$id['id'], time()])['c'];
    if ($cnt >= MAX_LISTINGS) { render_new($v, 'You already have '.MAX_LISTINGS.' active listings. End one first.'); return; }

    $key = random_bytes(32); $vt = tok(16); $rt = tok(16);
    try {
        db()->beginTransaction();
        $st = db()->prepare('INSERT INTO listings
            (identity_id, view_hash, remove_hash, view_enc, key_wrapped, title_enc, descr_enc, town_enc, town_hash, addr_enc,
             kind, private, mode, start_at, expires_at, weekly_len_min, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
        $st->bindValue(1, (int)$id['id'], PDO::PARAM_INT);
        $st->bindValue(2, hash('sha256', $vt));
        $st->bindValue(3, hash('sha256', $rt));
        $st->bindValue(4, enc($vt, mk()), PDO::PARAM_LOB);
        $st->bindValue(5, enc($key, mk()), PDO::PARAM_LOB);
        $st->bindValue(6, enc($v['title'], $key), PDO::PARAM_LOB);
        $st->bindValue(7, enc($v['descr'], $key), PDO::PARAM_LOB);
        $st->bindValue(8, enc($v['town'], $key), PDO::PARAM_LOB);
        $st->bindValue(9, town_hash($v['town']));
        $st->bindValue(10, enc($v['addr'], $key), PDO::PARAM_LOB);
        $st->bindValue(11, $v['kind']);
        $st->bindValue(12, $v['private'], PDO::PARAM_INT);
        $st->bindValue(13, $v['mode']);
        $st->bindValue(14, $start, PDO::PARAM_INT);
        $st->bindValue(15, $expires, PDO::PARAM_INT);
        if ($len === null) $st->bindValue(16, null, PDO::PARAM_NULL);
        else $st->bindValue(16, $len, PDO::PARAM_INT);
        $st->bindValue(17, time(), PDO::PARAM_INT);
        $st->execute();
        $lid = (int)db()->lastInsertId();
        foreach ($files as $f) store_photo($f, $key, $lid);
        db()->commit();
    } catch (Throwable $e) {
        if (db()->inTransaction()) db()->rollBack();
        error_log('gs create: '.get_class($e).': '.$e->getMessage().' @ '.$e->getFile().':'.$e->getLine());
        $msg = $e instanceof RuntimeException ? $e->getMessage() : 'Server error while creating the listing.';
        if (GS_DEBUG) $msg .= ' [DEBUG '.get_class($e).': '.$e->getMessage().' @ '.basename($e->getFile()).':'.$e->getLine().']';
        render_new($v, $msg);
        return;
    }
    render_created($vt, $rt, $v, $expires);
}

function render_created(string $vt, string $rt, array $v, int $expires): void {
    $share = h(base_url().'?s='.$vt);
    $remove = h(base_url().'?a=remove&t='.$rt);
    $expH = h(fmt_dt($expires));
    $what = $v['kind'] === 'market' ? 'market listing' : 'sale';
    $vtH = h($vt);
    page('Sale created', <<<HTML
<h1>✅ Your $what is live</h1>
<div class="card">
  <h2>Share link — send this to buyers</h2>
  <div class="copybox"><input id="share" readonly value="$share"><button type="button" onclick="copyBtn(this,'share')">Copy</button></div>
  <p class="muted">Anyone with this link can view photos and comment until $expH.</p>
  <p><a class="btn" href="?s=$vtH">Open the page</a></p>
</div>
<div class="card" style="border-color:#f0c4c0">
  <h2>🔥 Remove link — save it now</h2>
  <div class="copybox"><input id="remove" readonly value="$remove"><button type="button" onclick="copyBtn(this,'remove')">Copy</button></div>
  <p class="muted"><b>Shown only once.</b> It instantly deletes this listing, its photos and comments — no login needed. Keep it in your notes or password manager. If you lose it, you can still end the sale from this browser under My sales.</p>
</div>
<div class="card">
  <h2>Managing it</h2>
  <ul>
    <li>This browser now holds your secret seller cookie — <a href="?a=mine">My sales</a> lists everything you own.</li>
    <li>You can delete comments (✕) on the sale page.</li>
    <li>Everything auto-erases at expiry ($expH).</li>
  </ul>
</div>
HTML);
}

function act_view(): void {
    $t = (string)($_GET['s'] ?? '');
    $l = find_by_view($t);
    if (!$l) {
        http_response_code(404);
        page('Not found', '<div class="card"><h2>Link not valid</h2><p>This sale may have been removed, burned, or the link is mistyped.</p></div>');
        return;
    }
    if ((int)$l['expires_at'] <= time()) {
        q('DELETE FROM listings WHERE id=?', [$l['id']]);
        http_response_code(410);
        page('Sale ended', '<div class="card"><h2>This sale has ended</h2><p>It expired and everything was automatically erased.</p><p><a class="btn" href="?">Browse live sales</a></p></div>');
        return;
    }
    $key = listing_key($l);
    $title = dec($l['title_enc'], $key);
    $descr = dec($l['descr_enc'], $key);
    $town  = dec($l['town_enc'], $key);
    $addr  = dec($l['addr_enc'], $key);
    $isOwner = owner_of($l);
    $now = time();

    $kindBadge = $l['kind']==='market' ? '<span class="badge market">🥕 Farmers market</span>' : '<span class="badge">🏷 Garage sale</span>';
    $privBadge = $l['private'] ? '<span class="badge priv">🔒 Unlisted</span>' : '';

    if ($l['mode'] === 'short') {
        $sched = (int)$l['start_at'] > $now
            ? '🗓 Starts '.h(fmt_dt((int)$l['start_at'])).' (in '.h(span_left((int)$l['start_at']-$now)).') · open until '.h(fmt_dt((int)$l['expires_at']))
            : '🗓 '.h(fmt_dt((int)$l['start_at'])).' → '.h(fmt_dt((int)$l['expires_at'])).' · <b>closes in '.h(span_left((int)$l['expires_at']-$now)).'</b>';
    } else {
        $nx = next_occurrence($l); $open = '';
        if ($nx) {
            [$s, $e] = $nx;
            $open = ($now >= $s && $now < $e)
                ? '<span class="badge open">OPEN NOW</span> until '.h(fmt_t($e)).' today'
                : 'Next: <b>'.h(fmt_dt($s)).'</b> (in '.h(span_left($s-$now)).')';
        }
        $sched = '🗓 '.h(weekly_summary($l)).'<br>'.$open.' <span class="muted">· weekly until '.h(fmt_d((int)$l['expires_at'])).'</span>';
    }

    $photos = q('SELECT id FROM photos WHERE listing_id=? ORDER BY id', [$l['id']])->fetchAll();
    $photoHtml = '';
    foreach ($photos as $i => $p) {
        $u = '?a=img&s='.urlencode($t).'&p='.$p['id'];
        $photoHtml .= '<a href="'.h($u).'" target="_blank" rel="noopener"><img loading="lazy" src="'.h($u.'&th=1').'" alt="Sale photo '.($i+1).'"></a>';
    }
    if (!$photoHtml) $photoHtml = '<p class="muted">No photos posted.</p>';

    $csrf = $isOwner ? csrf_token() : '';
    $comments = q('SELECT * FROM comments WHERE listing_id=? ORDER BY id', [$l['id']])->fetchAll();
    $commentHtml = '';
    foreach ($comments as $c) {
        $nm = dec($c['name_enc'], $key);
        $bd = dec($c['body_enc'], $key);
        $del = $isOwner
            ? '<form class="inline" method="post" action="?a=delcomment" onsubmit="return confirm(\'Delete this comment?\')">'
              .'<input type="hidden" name="csrf" value="'.h($csrf).'"><input type="hidden" name="cid" value="'.$c['id'].'">'
              .'<input type="hidden" name="s" value="'.h($t).'"><button class="linklike" title="Delete comment">✕</button></form>'
            : '';
        $commentHtml .= '<div class="comment"><span class="who">'.h($nm).'</span><span class="when">'.h(ago((int)$c['created_at'])).'</span> '.$del
                      . '<div>'.nl2br(h($bd)).'</div></div>';
    }
    if (!$commentHtml) $commentHtml = '<p class="muted">No comments yet — ask about prices, sizes, or hold requests.</p>';

    $ownerBar = '';
    if ($isOwner) {
        $ownerBar = '<div class="card" style="border-color:#cfe3d4"><b>You own this listing.</b> '
            .'<span class="muted">Delete comments with ✕, or end it early.</span> '
            .'<form class="inline" method="post" action="?a=end" onsubmit="return confirm(\'End this sale now and erase everything?\')">'
            .'<input type="hidden" name="csrf" value="'.h($csrf).'"><input type="hidden" name="lid" value="'.$l['id'].'">'
            .'<button class="danger">End now</button></form> · <a href="?a=mine">My sales</a></div>';
    }

    $titleH = h($title);
    $addrLine = $addr !== '' ? h($addr).' · '.h($town) : h($town);
    $descHtml = $descr !== '' ? '<p>'.nl2br(h($descr)).'</p>' : '';
    $shareH = h(base_url().'?s='.$t);
    $tH = h($t);
    $expH = h(fmt_dt((int)$l['expires_at']));
    $n = count($comments);
    page($title, <<<HTML
$ownerBar
<div class="card">
  <div>$kindBadge $privBadge</div>
  <h1>$titleH</h1>
  <p>📍 $addrLine</p>
  <p class="muted">$sched</p>
  $descHtml
  <div class="photos">$photoHtml</div>
  <div class="copybox"><input id="shareV" readonly value="$shareH"><button type="button" onclick="copyBtn(this,'shareV')">Copy share link</button></div>
</div>
<div class="card" id="comments">
  <h2>💬 Comments ($n)</h2>
  $commentHtml
  <form method="post" action="?a=comment&s=$tH">
    <label>Display name (optional)<input name="cname" maxlength="40" placeholder="Anonymous"></label>
    <label>Comment<textarea name="body" rows="3" required maxlength="1000" placeholder="Is the drill still available? Can you hold it till noon?"></textarea></label>
    <div class="hp" aria-hidden="true"><label>Leave this empty<input name="url" tabindex="-1" autocomplete="off"></label></div>
    <p><button>Post comment</button></p>
    <p class="muted">Comments close $expH. The seller can delete comments. No account needed.</p>
  </form>
</div>
HTML);
}

function act_img(): void {
    $t = (string)($_GET['s'] ?? '');
    $pid = (int)($_GET['p'] ?? 0);
    $th = !empty($_GET['th']);
    $l = find_by_view($t);
    if (!$l) { http_response_code(404); exit; }
    if ((int)$l['expires_at'] <= time()) {
        q('DELETE FROM listings WHERE id=?', [$l['id']]);
        http_response_code(404); exit;
    }
    $et = '"p'.$pid.($th?'t':'f').'"';
    if (($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === $et) { http_response_code(304); exit; }
    $p = row('SELECT blob, thumb FROM photos WHERE id=? AND listing_id=?', [$pid, $l['id']]);
    if (!$p) { http_response_code(404); exit; }
    $data = dec($th ? $p['thumb'] : $p['blob'], listing_key($l));
    header('Content-Type: image/jpeg');
    header('Cache-Control: private, max-age=86400');
    header('ETag: '.$et);
    header('Content-Length: '.strlen($data));
    header('Content-Disposition: inline; filename="sale-photo.jpg"');
    echo $data;
    exit;
}

function act_comment(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') go('?');
    $t = (string)($_GET['s'] ?? '');
    $back = '<p><a href="'.h('?s='.urlencode($t)).'">← Back to the sale</a></p>';
    $l = find_by_view($t);
    if (!$l) { http_response_code(404); page('Not found', '<div class="card"><h2>Link not valid</h2>'.$back.'</div>'); return; }
    if ((int)$l['expires_at'] <= time()) {
        q('DELETE FROM listings WHERE id=?', [$l['id']]);
        http_response_code(410); page('Sale ended', '<div class="card"><h2>This sale has ended</h2><p>Comments are closed and everything was erased.</p></div>'); return;
    }
    if (trim((string)($_POST['url'] ?? '')) !== '') { http_response_code(400); page('Blocked', '<div class="card"><h2>Spam blocked</h2>'.$back.'</div>'); return; }
    $name = trim((string)($_POST['cname'] ?? ''));
    if ($name === '') $name = 'Anonymous';
    $body = trim((string)($_POST['body'] ?? ''));
    if ($body === '' || ulen($body) > 1000 || ulen($name) > 40) {
        http_response_code(400); page('Check your comment', '<div class="card"><h2>Comment not posted</h2><p>Comments need 1–1000 characters; names max 40.</p>'.$back.'</div>'); return;
    }
    $cc = (int)row('SELECT COUNT(*) c FROM comments WHERE listing_id=?', [$l['id']])['c'];
    if ($cc >= MAX_COMMENTS) { page('Comments full', '<div class="card"><h2>Comments are full</h2>'.$back.'</div>'); return; }
    $ipk = 'c:'.hash_hmac('sha256', (string)($_SERVER['REMOTE_ADDR'] ?? ''), mk());
    $th = row('SELECT last_at FROM throttle WHERE k=?', [$ipk]);
    if ($th && time() - (int)$th['last_at'] < COMMENT_COOLDOWN) {
        http_response_code(429); page('Slow down', '<div class="card"><h2>One moment…</h2><p>Wait a few seconds before commenting again.</p>'.$back.'</div>'); return;
    }
    $key = listing_key($l);
    $st = db()->prepare('INSERT INTO comments (listing_id, name_enc, body_enc, created_at) VALUES (?,?,?,?)');
    $st->bindValue(1, (int)$l['id'], PDO::PARAM_INT);
    $st->bindValue(2, enc($name, $key), PDO::PARAM_LOB);
    $st->bindValue(3, enc($body, $key), PDO::PARAM_LOB);
    $st->bindValue(4, time(), PDO::PARAM_INT);
    $st->execute();
    q('INSERT INTO throttle (k, last_at) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET last_at=excluded.last_at', [$ipk, time()]);
    go('?s='.urlencode($t).'#comments');
}

function act_delcomment(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') go('?');
    $c = row('SELECT c.id, l.identity_id FROM comments c JOIN listings l ON l.id=c.listing_id WHERE c.id=?', [(int)($_POST['cid'] ?? 0)]);
    $id = current_identity();
    if (!$c || !$id || (int)$c['identity_id'] !== (int)$id['id']) { http_response_code(403); page('Not allowed', '<div class="card"><h2>Not allowed</h2></div>'); return; }
    csrf_check();
    q('DELETE FROM comments WHERE id=?', [$c['id']]);
    $s = (string)($_POST['s'] ?? '');
    go($s !== '' ? '?s='.urlencode($s).'#comments' : '?a=mine');
}

function act_end(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') go('?a=mine');
    $l = row('SELECT * FROM listings WHERE id=?', [(int)($_POST['lid'] ?? 0)]);
    $id = current_identity();
    if (!$l || !$id || (int)$l['identity_id'] !== (int)$id['id']) { http_response_code(403); page('Not allowed', '<div class="card"><h2>Not allowed</h2></div>'); return; }
    csrf_check();
    q('DELETE FROM listings WHERE id=?', [$l['id']]);
    go('?a=mine');
}

function act_remove(): void {
    $t = (string)($_REQUEST['t'] ?? '');
    $l = preg_match('/^[A-Za-z0-9_-]{16,64}$/', $t)
        ? row('SELECT * FROM listings WHERE remove_hash=?', [hash('sha256', $t)]) : null;
    if (!$l) {
        http_response_code(404);
        page('Remove link', '<div class="card"><h2>Nothing to remove</h2><p>This remove link is invalid, or the listing is already gone.</p><p><a class="btn" href="?">Home</a></p></div>');
        return;
    }
    if ((int)$l['expires_at'] <= time()) {
        q('DELETE FROM listings WHERE id=?', [$l['id']]);
        page('Already ended', '<div class="card"><h2>Already ended</h2><p>It expired and auto-erased before this link was used.</p></div>');
        return;
    }
    $title = dec($l['title_enc'], listing_key($l));
    $titleH = h($title);
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        q('DELETE FROM listings WHERE id=?', [$l['id']]);
        page('Removed', '<div class="card"><h2>🗑 “'.$titleH.'” removed</h2><p>Photos and comments were erased and the share link is now dead.</p><p><a class="btn" href="?">Back home</a></p></div>');
        return;
    }
    $tH = h($t);
    $vtH = h(dec($l['view_enc'], mk()));
    page('Confirm removal', <<<HTML
<div class="card" style="border-color:#f0c4c0">
  <h2>Remove “$titleH”?</h2>
  <p>This permanently deletes the listing, all photos and all comments. The share link stops working immediately. There is no undo.</p>
  <form method="post" action="?a=remove">
    <input type="hidden" name="t" value="$tH">
    <p><button class="danger">Delete it now</button> <a class="btn ghost" href="?s=$vtH">Cancel — view the sale</a></p>
  </form>
</div>
HTML);
}

function act_mine(): void {
    $id = current_identity();
    if (!$id) {
        page('My sales', '<div class="card"><h2>No seller identity in this browser</h2><p class="muted">Sales are managed by a secret cookie, not a password. Create a sale and this browser becomes its owner. If you cleared cookies, use the remove link you saved to take a listing down.</p><p><a class="btn" href="?a=new">Create a sale</a></p></div>');
        return;
    }
    purge_expired();
    $rows = q('SELECT * FROM listings WHERE identity_id=? ORDER BY created_at DESC', [$id['id']])->fetchAll();
    $csrfH = h(csrf_token());
    $cards = '';
    foreach ($rows as $r) {
        $k = listing_key($r);
        $tiH = h(dec($r['title_enc'], $k));
        $vt = dec($r['view_enc'], mk());
        $vtH = h($vt);
        $shareH = h(base_url().'?s='.$vt);
        $badge = ($r['kind']==='market' ? '<span class="badge market">Market</span>' : '<span class="badge">Garage sale</span>')
               . ($r['private'] ? '<span class="badge priv">🔒 Unlisted</span>' : '');
        $agoH = h(ago((int)$r['created_at']));
        if ($r['mode'] === 'weekly') {
            $nx = next_occurrence($r);
            $when = $nx ? 'next '.h(fmt_dt($nx[0])) : 'finished';
        } else {
            $when = 'closes in '.h(span_left((int)$r['expires_at'] - time()));
        }
        $sid = 'sh'.$r['id'];
        $rid = (int)$r['id'];
        $cards .= <<<CARD
<div class="card">
  <div>$badge</div>
  <h2>$tiH</h2>
  <p class="muted">Created $agoH · $when</p>
  <div class="copybox"><input id="$sid" readonly value="$shareH"><button type="button" onclick="copyBtn(this,'$sid')">Copy share link</button></div>
  <p><a class="btn ghost" href="?s=$vtH">Open</a>
  <form class="inline" method="post" action="?a=end" onsubmit="return confirm('End this listing now and erase its photos and comments?')">
    <input type="hidden" name="csrf" value="$csrfH"><input type="hidden" name="lid" value="$rid">
    <button class="danger">End now</button>
  </form></p>
</div>
CARD;
    }
    if (!$cards) $cards = '<div class="card"><p class="muted">Nothing here yet. <a href="?a=new">Create a sale →</a></p></div>';
    page('My sales', <<<HTML
<h1>My sales</h1>
<p class="muted">This browser's secret cookie owns the listings below. Clearing cookies loses management access — the remove links you saved still work.</p>
$cards
<div class="card" style="border-color:#f0c4c0">
  <h2>🔥 Burn this identity</h2>
  <p class="muted">Permanently erases <b>every listing, photo and comment</b> owned by this browser and clears the seller cookie. Saved remove links will have nothing left to remove. There is no undo.</p>
  <form method="post" action="?a=burn" onsubmit="return confirm('Really burn everything?')">
    <input type="hidden" name="csrf" value="$csrfH">
    <div class="row"><input name="confirm" style="flex:1" placeholder="Type BURN to confirm" pattern="BURN" required autocomplete="off"><button class="danger">Burn identity</button></div>
  </form>
</div>
HTML);
}

function act_burn(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') go('?a=mine');
    $id = current_identity();
    if (!$id) { http_response_code(403); page('Not allowed', '<div class="card"><h2>No identity to burn</h2></div>'); return; }
    csrf_check();
    if (($_POST['confirm'] ?? '') !== 'BURN') {
        page('Not burned', '<div class="card"><h2>Not burned</h2><p>Type BURN (capitals) to confirm. <a href="?a=mine">Back</a></p></div>');
        return;
    }
    $lc = (int)row('SELECT COUNT(*) c FROM listings WHERE identity_id=?', [$id['id']])['c'];
    $pc = (int)row('SELECT COUNT(*) c FROM photos p JOIN listings l ON l.id=p.listing_id WHERE l.identity_id=?', [$id['id']])['c'];
    $cc = (int)row('SELECT COUNT(*) c FROM comments c JOIN listings l ON l.id=c.listing_id WHERE l.identity_id=?', [$id['id']])['c'];
    q('DELETE FROM identities WHERE id=?', [$id['id']]); // cascades listings → photos, comments
    setcookie('gs_id', '', ['expires'=>time()-3600, 'path'=>'/', 'httponly'=>true, 'secure'=>is_https(), 'samesite'=>'Lax']);
    page('Identity burned', '<div class="card"><h2>🔥 Identity burned</h2><p>'.$lc.' listing(s), '.$pc.' photo(s) and '.$cc.' comment(s) were erased. The seller cookie has been cleared. This browser is a stranger again.</p><p><a class="btn" href="?">Home</a></p></div>');
}

/* ---------------- page shell ---------------- */

const CSS = <<<'CSS'
:root{--bg:#f6f4ef;--card:#fff;--ink:#26221b;--mut:#7a7466;--acc:#2f7d4f;--acc2:#1d5c38;--bad:#b3261e;--line:#e5e0d5;--rad:14px}
*{box-sizing:border-box}
body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--ink)}
.top{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;background:#fff;border-bottom:1px solid var(--line);flex-wrap:wrap;gap:8px}
.brand{font-weight:800;font-size:20px;text-decoration:none;color:var(--ink)}
nav a{margin-left:14px;color:var(--acc2);text-decoration:none;font-weight:600}
main{max-width:960px;margin:0 auto;padding:20px}
footer{max-width:960px;margin:10px auto 40px;padding:0 20px;color:var(--mut);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--rad);padding:18px;margin:0 0 16px}
h1{font-size:26px;margin:6px 0 12px}h2{font-size:19px;margin:0 0 10px}
.muted{color:var(--mut);font-size:14px}
.badge{display:inline-block;font-size:12px;font-weight:700;padding:2px 9px;border-radius:99px;background:#e8f2ea;color:var(--acc2);margin-right:6px}
.badge.market{background:#fdf1e2;color:#8a5a17}.badge.priv{background:#eee;color:#555}.badge.open{background:var(--acc);color:#fff}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:14px}
.photos{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin:12px 0}
.photos img{width:100%;height:150px;object-fit:cover;border-radius:10px;display:block}
.thumb{width:100%;height:140px;object-fit:cover;border-radius:10px;background:#eee}
label{display:block;font-weight:600;font-size:14px;margin:12px 0 4px}
input,select,textarea{width:100%;padding:10px;border:1px solid var(--line);border-radius:10px;font:inherit;background:#fff}
input[type=checkbox],input[type=radio],input[type=file]{width:auto}
button,.btn{display:inline-block;background:var(--acc);color:#fff;border:0;border-radius:10px;padding:10px 18px;font:inherit;font-weight:700;cursor:pointer;text-decoration:none}
button:hover,.btn:hover{background:var(--acc2)}
.btn.ghost{background:#fff;color:var(--acc2);border:1px solid var(--acc)}
button.danger{background:var(--bad)}
button.linklike{background:none;color:var(--bad);padding:2px 6px;font-size:14px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.copybox{display:flex;gap:8px;margin:6px 0}.copybox input{flex:1;font-size:14px}
.comment{border-top:1px solid var(--line);padding:10px 0}
.comment .who{font-weight:700;font-size:14px}.comment .when{color:var(--mut);font-size:12px;margin-left:8px}
.hp{display:none}
.err{background:#fbe9e7;border:1px solid #f0c4c0;color:var(--bad);padding:12px;border-radius:10px;margin-bottom:14px}
.inline{display:inline}
fieldset{border:1px solid var(--line);border-radius:10px;margin:12px 0;padding:10px 14px}
legend{font-weight:700;font-size:14px;padding:0 6px}
CSS;

const JS = <<<'JS'
function copyBtn(btn,id){var el=document.getElementById(id);if(el.select)el.select();
navigator.clipboard.writeText(el.value||el.textContent).then(function(){var t=btn.textContent;btn.textContent='Copied ✓';setTimeout(function(){btn.textContent=t},1500)});}
function modeSwap(){var w=document.querySelector('input[name="mode"]:checked');if(!w)return;
var weekly=w.value==='weekly';var s=document.getElementById('m-short'),k=document.getElementById('m-weekly');
if(s)s.style.display=weekly?'none':'block';if(k)k.style.display=weekly?'block':'none';}
document.addEventListener('DOMContentLoaded',modeSwap);
JS;

function page(string $title, string $body): void {
    header('Content-Type: text/html; charset=utf-8');
    $t = h($title);
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
       . '<meta name="viewport" content="width=device-width,initial-scale=1">'
       . '<meta name="robots" content="noindex,nofollow">'
       . '<title>'.$t.' · SaleShed</title><style>'.CSS.'</style></head><body>'
       . '<header class="top"><a class="brand" href="?">🏷 SaleShed</a>'
       . '<nav><a href="?a=new">Create a sale</a><a href="?a=mine">My sales</a></nav></header>'
       . '<main>'.$body.'</main>'
       . '<footer>Encrypted at rest · EXIF/GPS stripped · No accounts · No IP logs · Listings auto-erase at expiry</footer>'
       . '<script>'.JS.'</script></body></html>';
}

/* ---------------- dispatch ---------------- */

if (PHP_SAPI === 'cli') {
    boot();
    if (($argv[1] ?? '') === 'purge') echo 'Purged '.purge_expired()." expired listing(s)\n";
    else echo "Usage: php garage.php purge\n";
    exit;
}

boot();
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; img-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('Cache-Control: no-store');

$a = (string)($_GET['a'] ?? (isset($_GET['s']) ? 'view' : 'home'));
$map = [
    'home'=>'act_home', 'new'=>'act_new', 'create'=>'act_create', 'view'=>'act_view',
    'img'=>'act_img', 'comment'=>'act_comment', 'delcomment'=>'act_delcomment',
    'mine'=>'act_mine', 'end'=>'act_end', 'remove'=>'act_remove', 'burn'=>'act_burn',
];
try {
    if (!isset($map[$a])) { http_response_code(404); page('Not found', '<div class="card"><h2>Page not found</h2></div>'); }
    else $map[$a]();
} catch (Throwable $e) {
    error_log('gs: '.$e->getMessage());
    http_response_code(500);
    if ($a === 'img') exit;
    page('Error', '<div class="card"><h2>Something went wrong</h2><p class="muted">The server hit an error. If it persists, check the PHP error log (and that master.key is intact).</p></div>');
}