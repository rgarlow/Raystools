<?php
// Ray's Tools hub: one login, controls every site that has the SiteBridge plugin.
declare(strict_types=1);

$config = require __DIR__ . '/config.php';
$sitesFile = __DIR__ . '/data/sites.json';

session_set_cookie_params( array( 'httponly' => true, 'samesite' => 'Strict', 'secure' => ! empty( $_SERVER['HTTPS'] ) ) );
session_start();

function h( $s ): string {
    return htmlspecialchars( (string) $s, ENT_QUOTES, 'UTF-8' );
}

function load_sites( string $file ): array {
    if ( ! is_file( $file ) ) {
        return array();
    }
    $d = json_decode( (string) file_get_contents( $file ), true );
    return is_array( $d ) ? $d : array();
}

function save_sites( string $file, array $sites ): void {
    if ( ! is_dir( dirname( $file ) ) ) {
        mkdir( dirname( $file ), 0750, true );
    }
    file_put_contents( $file, json_encode( $sites, JSON_PRETTY_PRINT ), LOCK_EX );
}

function remote_call( array $site, string $do, bool $raw = false ) {
    $time = (string) time() . '-' . bin2hex( random_bytes( 6 ) );
    $sig  = hash_hmac( 'sha256', $time . '.' . $do, $site['key'] );
    $host = (string) parse_url( $site['url'], PHP_URL_HOST );
    $local = in_array( $host, array( 'localhost', '127.0.0.1' ), true );
    $insecure = ! empty( $GLOBALS['config']['insecure_ssl'] ) && $local;
    $url  = rtrim( $site['url'], '/' ) . '/?rest_route=/sitebridge/v1/remote';
    $ch   = curl_init( $url );
    curl_setopt_array( $ch, array(
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query( array( 'do' => $do ) ),
        CURLOPT_HTTPHEADER     => array( 'X-SBM-Time: ' . $time, 'X-SBM-Sig: ' . $sig ),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 'dbbackup' === $do ? 300 : 30,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => ! $insecure,
        CURLOPT_SSL_VERIFYHOST => $insecure ? 0 : 2,
    ) );
    $body = curl_exec( $ch );
    $code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
    $err  = curl_error( $ch );
    curl_close( $ch );
    if ( false === $body ) {
        return array( 'ok' => false, 'message' => 'Could not reach site: ' . $err );
    }
    if ( $raw && 200 === $code ) {
        return $body;
    }
    $json = json_decode( (string) $body, true );
    if ( 200 !== $code || ! is_array( $json ) ) {
        return array( 'ok' => false, 'message' => 'Site refused (HTTP ' . $code . '). Check the key and that the plugin is active.' );
    }
    return $json;
}

// ---- Auth ----
header( 'X-Frame-Options: DENY' );
header( 'X-Content-Type-Options: nosniff' );
header( 'Referrer-Policy: no-referrer' );
header( 'Cache-Control: no-store' );

$lockFile = __DIR__ . '/data/lock-' . md5( $_SERVER['REMOTE_ADDR'] ?? '' ) . '.json';
$lock     = is_file( $lockFile ) ? json_decode( (string) file_get_contents( $lockFile ), true ) : array();
$lock     = is_array( $lock ) ? $lock : array();
$locked   = ( $lock['count'] ?? 0 ) >= 5 && time() - ( $lock['time'] ?? 0 ) < 900;

$error = '';
if ( isset( $_POST['login'] ) ) {
    if ( $locked ) {
        $error = 'Too many attempts. Try again in 15 minutes.';
    } elseif ( password_verify( (string) ( $_POST['password'] ?? '' ), $config['password_hash'] ) ) {
        @unlink( $lockFile );
        session_regenerate_id( true );
        $_SESSION = array( 'auth' => true, 'csrf' => bin2hex( random_bytes( 16 ) ) );
        header( 'Location: ./' );
        exit;
    } else {
        $count = ( time() - ( $lock['time'] ?? 0 ) < 900 ? ( $lock['count'] ?? 0 ) : 0 ) + 1;
        file_put_contents( $lockFile, json_encode( array( 'count' => $count, 'time' => time() ) ), LOCK_EX );
        $error = 'Wrong password.';
    }
}

if ( isset( $_GET['logout'] ) ) {
    $_SESSION = array();
    session_destroy();
    header( 'Location: ./' );
    exit;
}

if ( empty( $_SESSION['auth'] ) ) {
    ?><!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ray's Tools</title>
<style>body{font:16px system-ui;background:#1d2a5c;display:grid;place-items:center;height:100vh;margin:0}form{background:#fff;padding:28px;border-radius:12px;width:300px}input,button{width:100%;padding:10px;margin-top:10px;box-sizing:border-box;font-size:16px}button{background:#2065d1;color:#fff;border:0;border-radius:6px;cursor:pointer}</style>
<form method="post"><h2 style="margin:0">Ray's Tools</h2><input type="password" name="password" placeholder="Password" autofocus required><button name="login" value="1">Log in</button><p style="color:#b32d2e"><?= h( $error ) ?></p></form><?php
    exit;
}

$csrf  = $_SESSION['csrf'];
$sites = load_sites( $sitesFile );
$flash = '';

if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
    if ( ! hash_equals( $csrf, (string) ( $_POST['csrf'] ?? '' ) ) ) {
        http_response_code( 400 );
        exit( 'Bad request token.' );
    }
    $act = (string) ( $_POST['act'] ?? '' );
    $id  = (string) ( $_POST['site'] ?? '' );

    if ( 'add' === $act ) {
        $name = trim( (string) ( $_POST['name'] ?? '' ) );
        $url  = trim( (string) ( $_POST['url'] ?? '' ) );
        $key  = trim( (string) ( $_POST['key'] ?? '' ) );
        $okurl = preg_match( '#^https://#i', $url ) || ( ! empty( $config['insecure_ssl'] ) && preg_match( '#^http://(localhost|127\.0\.0\.1)([:/]|$)#i', $url ) );
        if ( '' !== $name && $okurl && strlen( $key ) >= 32 ) {
            $sites[ bin2hex( random_bytes( 4 ) ) ] = array( 'name' => $name, 'url' => rtrim( $url, '/' ), 'key' => $key );
            save_sites( $sitesFile, $sites );
            $flash = 'Site added.';
        } else {
            $flash = 'Need a name, an https:// address and the key.';
        }
    } elseif ( 'remove' === $act && isset( $sites[ $id ] ) ) {
        unset( $sites[ $id ] );
        save_sites( $sitesFile, $sites );
        $flash = 'Site removed.';
    } elseif ( in_array( $act, array( 'permalinks', 'flush', 'cache' ), true ) && isset( $sites[ $id ] ) ) {
        $r     = remote_call( $sites[ $id ], $act );
        $flash = $sites[ $id ]['name'] . ': ' . ( $r['message'] ?? 'Done.' );
    } elseif ( 'dbbackup' === $act && isset( $sites[ $id ] ) ) {
        $r = remote_call( $sites[ $id ], 'dbbackup', true );
        if ( is_string( $r ) ) {
            header( 'Content-Type: application/sql' );
            header( 'Content-Disposition: attachment; filename="' . preg_replace( '/[^a-z0-9]+/i', '-', $sites[ $id ]['name'] ) . '-backup-' . gmdate( 'Ymd-His' ) . '.sql"' );
            echo $r;
            exit;
        }
        $flash = $r['message'] ?? 'Backup failed.';
    }
}

function bytes( $b ): string {
    return $b ? round( $b / 1073741824, 1 ) . ' GB' : '?';
}
?><!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ray's Tools</title>
<style>
body{font:15px system-ui;background:#f1f3f7;margin:0;color:#1d2327}
header{background:linear-gradient(135deg,#1d2a5c,#2065d1);color:#fff;padding:20px 28px;display:flex;justify-content:space-between;align-items:center}
header a{color:#fff}main{max-width:1100px;margin:20px auto;padding:0 16px}
.card{background:#fff;border:1px solid #dcdfe6;border-radius:12px;padding:18px;margin-bottom:18px}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin:10px 0}.stats span{background:#f1f3f7;border-radius:8px;padding:6px 10px}
.btns{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.btns form{margin:0}
button{padding:9px 14px;border:0;border-radius:8px;color:#fff;cursor:pointer;font:inherit}
.b{background:#2065d1}.g{background:#2f9e44}.o{background:#e8590c}.r{background:#b32d2e}
.flash{background:#e7f6ec;border-left:4px solid #1a7f37;padding:10px 14px;border-radius:4px;margin-bottom:16px}
.bad{color:#b32d2e}.ok{color:#1a7f37}input{padding:8px;margin:4px 4px 4px 0;font:inherit}
a.lnk{color:#2065d1;text-decoration:none;padding:9px 6px}
</style>
<header><h1 style="margin:0">Ray's Tools</h1><a href="?logout=1">Log out</a></header>
<main>
<?php if ( $flash ) : ?><div class="flash"><?= h( $flash ) ?></div><?php endif; ?>

<?php foreach ( $sites as $id => $site ) :
    $res = remote_call( $site, 'status' );
    $st  = ! empty( $res['ok'] ) ? $res['status'] : null;
    ?>
<div class="card">
    <h2 style="margin:0"><?= h( $site['name'] ) ?> <small><a class="lnk" href="<?= h( $site['url'] ) ?>/" target="_blank" rel="noopener"><?= h( $site['url'] ) ?></a></small></h2>
    <?php if ( $st ) : ?>
    <div class="stats">
        <span><b><?= (int) $st['posts'] ?></b> posts</span>
        <span><b><?= (int) $st['drafts'] ?></b> drafts</span>
        <span><b><?= (int) $st['comments'] ?></b> comments waiting</span>
        <span>Disk free <b><?= h( bytes( $st['disk_free'] ) ) ?></b></span>
        <span>WP <?= h( $st['wp'] ) ?> · PHP <?= h( $st['php'] ) ?></span>
        <span class="<?= ( $st['target_permalinks'] ?? '' ) === $st['permalinks'] ? 'ok' : 'bad' ?>">Permalinks: <?= h( $st['permalinks'] ?: 'plain' ) ?></span>
    </div>
    <?php else : ?>
    <p class="bad"><?= h( $res['message'] ?? 'Unreachable' ) ?></p>
    <?php endif; ?>
    <div class="btns">
        <a class="lnk" href="<?= h( $site['url'] ) ?>/wp-admin/" target="_blank" rel="noopener">Open WP Admin</a>
        <a class="lnk" href="<?= h( $site['url'] ) ?>/wp-admin/post-new.php" target="_blank" rel="noopener">New Post</a>
        <?php foreach ( array( 'permalinks' => array( 'Fix Permalinks', 'g' ), 'flush' => array( 'Refresh Links', 'g' ), 'cache' => array( 'Clear Cache', 'g' ), 'dbbackup' => array( 'Backup Database', 'o' ) ) as $a => $l ) : ?>
        <form method="post"><input type="hidden" name="csrf" value="<?= h( $csrf ) ?>"><input type="hidden" name="site" value="<?= h( $id ) ?>"><button class="<?= $l[1] ?>" name="act" value="<?= $a ?>"><?= h( $l[0] ) ?></button></form>
        <?php endforeach; ?>
        <form method="post" onsubmit="return confirm('Remove this site from the hub?')"><input type="hidden" name="csrf" value="<?= h( $csrf ) ?>"><input type="hidden" name="site" value="<?= h( $id ) ?>"><button class="r" name="act" value="remove">Remove</button></form>
    </div>
</div>
<?php endforeach; ?>

<div class="card">
    <h3 style="margin-top:0">Add a site</h3>
    <p>On the site, open <b>Site Control</b> in WP admin and copy the key at the bottom.</p>
    <form method="post"><input type="hidden" name="csrf" value="<?= h( $csrf ) ?>">
        <input name="name" placeholder="Name" required>
        <input name="url" placeholder="https://tellmeadventurestory.com" size="34" required>
        <input name="key" placeholder="Remote key" size="40" required>
        <button class="b" name="act" value="add">Add site</button>
    </form>
</div>
</main>
