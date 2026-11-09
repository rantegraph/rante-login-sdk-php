<?php

/*
 * Sign in with Rante: a website on PHP's built-in web server that signs people in with the Rante Login SDK for PHP.
 *   php -S 127.0.0.1:3000 -t public public/index.php
 *
 * Three ways in, all finished and checked on this server:
 * - "Sign in with Rante" button (signin.js): the browser SDK with serverSide: true. In Chrome and Edge it uses FedCM
 *   and posts the ID token to /auth/rante/fedcm; elsewhere it redirects, and the code comes back to the redirect URI
 *   with the SDK's rante_login_* cookies.
 * - "Sign in without JavaScript" link: /auth/rante/sign-in builds the authorize request here
 *   (createAuthorizationRequest) and keeps its state, nonce and PKCE verifier in the session.
 * - Either redirect ends at the redirect URI, where handleCallback exchanges the code (private_key_jwt or PKCE alone)
 *   and validates the ID token.
 */

declare(strict_types=1);

use Rante\Login\BrowserSdkCookies;
use Rante\Login\ExpectedTransaction;
use Rante\Login\RanteLoginClient;
use Rante\Login\RanteLoginException;
use Rante\Login\SigningKey;
use Rante\Login\ValidatedIdToken;

$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (in_array($path, ['/signin.js', '/style.css'], true)) {
    return false; // the built-in server sends the file from public/
}

require __DIR__ . '/../../../vendor/autoload.php';

const SDK_SRC = 'https://login.rante.com/sdk/v1/rante-login.js';
const SDK_INTEGRITY = 'sha384-2W12/NktCjRqFuXWiUtHr1yEtdrjBlCRWnJ+//FZMiqd1KRX/K+YMWLoMgF9R7wf';

header('Content-Security-Policy: ' . implode('; ', [
    "default-src 'self'",
    "script-src 'self' https://login.rante.com", // the browser SDK, pinned by its integrity hash
    "connect-src 'self' https://login.rante.com", // FedCM fetches the identity provider's configuration
    "img-src 'self' data:",
    "style-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
]));
header('Referrer-Policy: same-origin');
header('X-Content-Type-Options: nosniff');

try {
    $keyPrefix = (string) getenv('RANTE_LOGIN_KEY_PREFIX');
    $keyFile = (string) getenv('RANTE_LOGIN_PRIVATE_KEY_FILE');
    if (($keyPrefix === '') !== ($keyFile === '')) {
        throw new RanteLoginException('invalid_configuration',
            'Set both RANTE_LOGIN_KEY_PREFIX and RANTE_LOGIN_PRIVATE_KEY_FILE (a server-side website), or neither (browser-only).');
    }
    $rante = new RanteLoginClient(
        (string) getenv('RANTE_LOGIN_CLIENT_ID'),
        getenv('RANTE_LOGIN_REDIRECT_URI') ?: 'http://localhost:3000/auth/rante/callback',
        signingKey: $keyFile !== '' ? SigningKey::fromPem($keyPrefix, (string) file_get_contents($keyFile)) : null,
        scope: getenv('RANTE_LOGIN_SCOPE') ?: 'openid profile email',
    );
} catch (RanteLoginException $error) {
    error_log('Configuration: ' . $error->getMessage());
    http_response_code(500);
    echo page('Configuration', '<h1>Configuration</h1><p class="error">' . e($error->getMessage()) . '</p>');
    return true;
}

$redirect = parse_url($rante->redirectUri);
$siteOrigin = $redirect['scheme'] . '://' . $redirect['host'] . (isset($redirect['port']) ? ':' . $redirect['port'] : '');
$callbackPath = $redirect['path'] ?? '/';
$secure = $redirect['scheme'] === 'https';

session_name('rante_php_session');
session_set_cookie_params(['path' => '/', 'httponly' => true, 'samesite' => 'Lax', 'secure' => $secure]);
// Strict mode: a session ID this server didn't issue is replaced, never adopted, and a malformed one can't make
// session_start() fail.
session_start(['use_strict_mode' => true]);

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
try {
    match (true) {
        $method === 'GET' && $path === '/' => home($rante),
        $method === 'GET' && $path === '/auth/rante/sign-in' => signIn($rante),
        $method === 'GET' && $path === $callbackPath => callback($rante, $secure),
        $method === 'POST' && $path === '/auth/rante/fedcm' => fedcm($rante, $siteOrigin),
        $method === 'GET' && $path === '/userinfo' => userinfo($rante),
        $method === 'POST' && $path === '/auth/sign-out' => signOut($siteOrigin, $secure),
        default => notFound(),
    };
} catch (RanteLoginException $error) {
    // Log the reason, never the code, the cookies or a token.
    error_log('Sign-in failed: ' . $error->errorCode . ': ' . $error->getMessage());
    $message = $error->errorCode === 'access_denied' ? 'The sign-in was cancelled on the Rante Login page.' : $error->getMessage();
    http_response_code(400);
    echo page('Sign-in failed', '<h1>Sign-in failed</h1><p class="error"><code>' . e($error->errorCode) . '</code> ' . e($message)
        . '</p><p><a href="/">Try again</a></p>');
}
return true;

function home(RanteLoginClient $rante): void
{
    header('Cache-Control: no-store');
    if (isset($_SESSION['user'])) {
        $user = $_SESSION['user'];
        $name = $user['claims']['name'] ?? null;
        echo page('Signed in', '<h1>Signed in' . (is_string($name) ? ' as ' . e($name) : '') . '</h1>'
            . '<p>Signed in with: <strong>' . e($user['method']) . '</strong>, ' . e($user['signedInAt']) . '</p>'
            . accountSection($user)
            . '<h2>ID token</h2>'
            . '<p>This server validated the ID token below. Use <code>sub</code> as the person\'s ID on this website: it is pairwise, '
            . 'so other organizations\' apps see a different value.</p>'
            . table($user['claims'])
            . '<p><a href="/userinfo">Show userinfo</a></p>'
            . '<form method="post" action="/auth/sign-out"><button type="submit">Sign out</button></form>');
        return;
    }
    // FedCM hands the ID token to the page, so its nonce must be one the page can't choose: issue it here and keep it
    // in the session. The browser SDK sends the same nonce in its redirect flow.
    $_SESSION['rante_nonce'] ??= rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    echo page('Sign in with Rante', '<h1>Sign in with Rante</h1>'
        . '<p>PHP example of the Rante Login SDK for PHP: the server finishes the sign-in and validates the ID token.</p>'
        . '<div id="rante-signin" data-client-id="' . e($rante->clientId) . '" data-redirect-uri="' . e($rante->redirectUri)
        . '" data-scope="' . e($rante->scope) . '" data-nonce="' . e($_SESSION['rante_nonce']) . '"></div>'
        . '<p id="rante-signin-status" role="status"></p>'
        . '<p><a href="/auth/rante/sign-in">Sign in without JavaScript</a> (the server starts the sign-in)</p>'
        . '<script src="' . SDK_SRC . '" integrity="' . SDK_INTEGRITY . '" crossorigin="anonymous"></script>'
        . '<script src="/signin.js"></script>');
}

// The server starts the sign-in: no JavaScript needed.
function signIn(RanteLoginClient $rante): void
{
    $request = $rante->createAuthorizationRequest();
    $_SESSION['rante_request'] = $request->toExpected()->toArray();
    header('Location: ' . $request->url, true, 303);
}

// The redirect URI: Rante Login comes back with ?code=...&state=...&iss=... (or ?error=...).
function callback(RanteLoginClient $rante, bool $secure): void
{
    // A sign-in this server started is in the session; one the browser SDK started is in its cookies. Both are used once.
    $started = ExpectedTransaction::fromArray($_SESSION['rante_request'] ?? null);
    unset($_SESSION['rante_request']);
    $fromBrowser = RanteLoginClient::fromBrowserSdkCookies($_COOKIE);
    foreach (BrowserSdkCookies::ALL as $name) {
        setcookie($name, '', ['expires' => 1, 'path' => '/', 'samesite' => 'Lax', 'secure' => $secure]);
    }
    $byServer = $started !== null && $started->state === ($_GET['state'] ?? null);
    // The raw query string, so that a repeated parameter is refused rather than silently collapsed by $_GET.
    $result = $rante->handleCallback($_SERVER['QUERY_STRING'] ?? '', $byServer ? $started : ($fromBrowser ?? $started));
    startSession($result->idToken, $result->accessToken(),
        ($byServer ? 'Redirect started by the server' : 'Redirect started by the browser SDK') . ', ' . $rante->clientAuthentication());
    header('Location: /', true, 303);
}

// FedCM: the page posts the ID token the browser's account dialog returned.
function fedcm(RanteLoginClient $rante, string $siteOrigin): void
{
    header('Content-Type: application/json');
    if (($_SERVER['HTTP_ORIGIN'] ?? '') !== $siteOrigin) {
        http_response_code(403);
        echo '{"error":"origin_not_allowed"}';
        return;
    }
    try {
        $nonce = $_SESSION['rante_nonce'] ?? null;
        if (!is_string($nonce)) {
            throw new RanteLoginException('missing_transaction', 'This browser session has no sign-in nonce. Reload the page.');
        }
        $body = str_starts_with($_SERVER['CONTENT_TYPE'] ?? '', 'application/json')
            ? json_decode((string) file_get_contents('php://input', length: 16 * 1024), true)
            : null;
        $idToken = is_array($body) && is_string($body['idToken'] ?? null) ? $body['idToken'] : null;
        startSession($rante->validateIdToken($idToken, $nonce), null, 'FedCM');
        http_response_code(204);
    } catch (RanteLoginException $error) {
        error_log('FedCM sign-in failed: ' . $error->errorCode . ': ' . $error->getMessage());
        http_response_code(400);
        echo json_encode(['error' => $error->errorCode]);
    }
}

// The person's claims from Rante Login's userinfo endpoint, with the access token from the code exchange (15 minutes).
function userinfo(RanteLoginClient $rante): void
{
    header('Cache-Control: no-store');
    $user = $_SESSION['user'] ?? null;
    if ($user === null) {
        header('Location: /', true, 303);
        return;
    }
    if ($user['accessToken'] === null) {
        echo page('Userinfo', '<h1>Userinfo</h1><p>FedCM sign-ins return only an ID token, so there is no access token to call userinfo with.</p>'
            . '<p><a href="/">Back</a></p>');
        return;
    }
    $info = $rante->fetchUserInfo($user['accessToken'], $user['claims']['sub']);
    echo page('Userinfo', '<h1>Userinfo</h1><p>From GET https://login.rante.com/common/oidc/v2.0/userinfo:</p>' . table($info->claims)
        . '<p><a href="/">Back</a></p>');
}

function signOut(string $siteOrigin, bool $secure): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin !== '' && $origin !== $siteOrigin) {
        http_response_code(403);
        return;
    }
    // Signs out of this website only; the person stays signed in to Rante.
    $_SESSION = [];
    session_destroy();
    setcookie(session_name(), '', ['expires' => 1, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax', 'secure' => $secure]);
    header('Location: /', true, 303);
}

// A new session ID for the person who signed in, so a session fixed before sign-in is worthless. The sign-in also creates
// or finds their account on this website.
function startSession(ValidatedIdToken $token, ?string $accessToken, string $method): void
{
    [, $created] = registerOrFind($token->claims);
    session_regenerate_id(true);
    $_SESSION = ['user' => ['claims' => $token->claims, 'accessToken' => $accessToken, 'method' => $method,
        'signedInAt' => gmdate('Y-m-d\TH:i:s\Z'), 'newAccount' => $created]];
}

/**
 * This website's own accounts. A person's first "Sign in with Rante" here is their sign-up: the account is created from
 * the claims they agreed to share, and every later sign-in finds it by `sub`. A real website keeps accounts in its
 * database; PHP keeps nothing in memory between requests, so this example keeps them in a JSON file in the temp folder
 * (it holds the names and emails of the people who signed in: delete it when you're done).
 *
 * @param array<string, mixed> $claims
 * @return array{0: array<string, mixed>, 1: bool} the account, and whether it was created now
 */
function registerOrFind(array $claims): array
{
    $handle = fopen(accountsFile(), 'c+');
    if ($handle === false) {
        throw new RuntimeException('The accounts file could not be opened.');
    }
    try {
        flock($handle, LOCK_EX);
        $accounts = json_decode((string) stream_get_contents($handle), true);
        $accounts = is_array($accounts) ? $accounts : [];
        $sub = (string) $claims['sub'];
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $created = !isset($accounts[$sub]);
        if ($created) {
            $accounts[$sub] = ['id' => uuid(), 'sub' => $sub, 'name' => null, 'email' => null, 'createdAt' => $now];
        }
        // Keep the details the person shares this time. Rante shares an email only once it's verified.
        $accounts[$sub]['name'] = is_string($claims['name'] ?? null) ? $claims['name'] : $accounts[$sub]['name'];
        $accounts[$sub]['email'] = is_string($claims['email'] ?? null) ? $claims['email'] : $accounts[$sub]['email'];
        $accounts[$sub]['lastSignInAt'] = $now;
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, (string) json_encode($accounts, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($handle);
        return [$accounts[$sub], $created];
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

/** @return array<string, mixed>|null */
function findAccount(string $sub): ?array
{
    $handle = @fopen(accountsFile(), 'r');
    if ($handle === false) {
        return null;
    }
    try {
        flock($handle, LOCK_SH);
        $accounts = json_decode((string) stream_get_contents($handle), true);
        return is_array($accounts) && isset($accounts[$sub]) ? $accounts[$sub] : null;
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

function accountsFile(): string
{
    return sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'rante-login-php-example-accounts.json';
}

function uuid(): string
{
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
}

/** @param array<string, mixed> $user */
function accountSection(array $user): string
{
    $account = findAccount((string) ($user['claims']['sub'] ?? ''));
    if ($account === null) {
        return '<h2>Your account on this website</h2><p>Not found: the accounts file was removed since you signed in. Sign out and '
            . 'in again.</p>';
    }
    $status = ($user['newAccount'] ?? false) === true
        ? 'Created at this sign-in from your Rante account: no separate sign-up form, and no password for this website.'
        : 'Welcome back: this sign-in found your account by its Rante ID.';
    return '<h2>Your account on this website</h2><p>' . e($status) . '</p><table><tbody>'
        . '<tr><th>Account ID</th><td>' . e((string) $account['id']) . '</td></tr>'
        . '<tr><th>Linked Rante ID (<code>sub</code>)</th><td>' . e((string) $account['sub']) . '</td></tr>'
        . '<tr><th>Name</th><td>' . e((string) ($account['name'] ?? 'not shared')) . '</td></tr>'
        . '<tr><th>Email</th><td>' . e((string) ($account['email'] ?? "not shared (Rante shares an email only once it's verified)")) . '</td></tr>'
        . '<tr><th>Created</th><td>' . e((string) $account['createdAt']) . '</td></tr>'
        . '<tr><th>Last sign-in</th><td>' . e((string) $account['lastSignInAt']) . '</td></tr>'
        . '</tbody></table>'
        . '<p>This example keeps accounts in a JSON file in the temp folder, because PHP keeps nothing in memory between requests. '
        . 'A real website stores them in its database, keyed by <code>sub</code>.</p>';
}

function notFound(): void
{
    http_response_code(404);
    echo page('Not found', '<h1>Not found</h1><p><a href="/">Home</a></p>');
}

/** @param array<string, mixed> $claims */
function table(array $claims): string
{
    $rows = '';
    foreach ($claims as $name => $value) {
        $text = is_scalar($value) ? (is_bool($value) ? ($value ? 'true' : 'false') : (string) $value) : (string) json_encode($value);
        $rows .= '<tr><th><code>' . e((string) $name) . '</code></th><td>' . e($text) . '</td></tr>';
    }
    return '<table><tbody>' . $rows . '</tbody></table>';
}

function page(string $title, string $body): string
{
    return "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n"
        . "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        . '  <title>' . e($title) . " - PHP example</title>\n  <link rel=\"stylesheet\" href=\"/style.css\">\n</head>\n"
        . "<body>\n  <main>\n" . $body . "\n  </main>\n</body>\n</html>\n";
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}
