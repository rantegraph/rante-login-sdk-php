<?php

declare(strict_types=1);

namespace Rante\Login;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Psr\SimpleCache\CacheInterface;
use Rante\Login\Http\CurlHttpClient;
use Rante\Login\Http\HttpClient;
use Rante\Login\Http\HttpResponse;

/**
 * "Sign in with Rante" on a PHP server, built on firebase/php-jwt.
 *
 * Rante Login is an OpenID Connect provider (issuer https://login.rante.com/common/v2.0) with the authorization code
 * flow with PKCE (S256), state, nonce and the iss response parameter (RFC 9207); client authentication by
 * private_key_jwt (RFC 7523) for server-side websites, or PKCE alone for browser-only websites; RS256 ID tokens with a
 * pairwise sub; and a userinfo endpoint.
 *
 * PHP keeps nothing between requests, so the client fetches the discovery document and the signing keys on each
 * request that needs them, unless you give it a PSR-16 cache.
 */
final class RanteLoginClient
{
    public const DEFAULT_ISSUER = 'https://login.rante.com/common/v2.0';

    private const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    private const ASSERTION_LIFETIME = 60; // Rante Login accepts at most 300 seconds.
    private const SCOPES = ['openid', 'profile', 'email', 'phone', 'address', 'rante.organization'];
    private const PROMPTS = ['none', 'login', 'consent', 'select_account'];
    private const JWKS_COOLDOWN = 30;

    public readonly string $clientId;
    public readonly string $redirectUri;
    public readonly string $scope;
    public readonly string $issuer;
    private readonly HttpClient $http;

    /** @var array<string, string>|null */
    private ?array $metadata = null;
    /** @var array<string, mixed>|null */
    private ?array $jwks = null;
    private int $jwksFetchedAt = 0;

    /**
     * @param string $clientId the app's Application (client) ID
     * @param string $redirectUri exactly as registered on the app
     * @param SigningKey|null $signingKey server-side websites: the Signed JWT key linked to the app; without it the
     *                                    client authenticates with PKCE alone (browser-only websites)
     * @param string $scope request only scopes whose information the app asks for
     * @param CacheInterface|null $cache keeps the discovery document (1 hour) and the signing keys (10 minutes)
     *                                   between requests
     * @param int $clockSkew seconds of clock skew allowed for the ID token
     */
    public function __construct(
        string $clientId,
        string $redirectUri,
        private readonly ?SigningKey $signingKey = null,
        string $scope = 'openid profile email',
        string $issuer = self::DEFAULT_ISSUER,
        ?HttpClient $http = null,
        private readonly ?CacheInterface $cache = null,
        int $timeout = 10,
        private readonly int $clockSkew = 60,
    ) {
        $this->clientId = self::normalizeClientId($clientId);
        $this->redirectUri = self::normalizeRedirectUri($redirectUri);
        $this->scope = self::normalizeScope($scope);
        $this->issuer = self::normalizeIssuer($issuer);
        $this->http = $http ?? new CurlHttpClient($timeout);
    }

    /** private_key_jwt with the app's Signed JWT key, or none (PKCE alone). */
    public function clientAuthentication(): string
    {
        return $this->signingKey === null ? 'none' : 'private_key_jwt';
    }

    /**
     * Starts a sign-in on the server: the URL to send the browser to, and the values to keep (in the session) until
     * the browser comes back to the redirect URI.
     */
    public function createAuthorizationRequest(?string $nonce = null, ?string $prompt = null, ?string $loginHint = null, ?int $maxAge = null): AuthorizationRequest
    {
        if ($nonce !== null && preg_match('/^[\x21-\x7e]{1,256}$/', $nonce) !== 1) {
            throw new RanteLoginException('invalid_request', 'nonce must be 1 to 256 printable ASCII characters without spaces.');
        }
        $prompt = self::checkPrompt($prompt);
        if ($loginHint !== null && strlen($loginHint) > 256) {
            throw new RanteLoginException('invalid_request', 'loginHint must be at most 256 characters.');
        }
        if ($maxAge !== null && $maxAge < 0) {
            throw new RanteLoginException('invalid_request', 'maxAge must be a whole number of seconds.');
        }
        $endpoint = $this->discover()['authorization_endpoint'];
        $nonce ??= self::randomToken();
        $state = self::randomToken();
        $codeVerifier = self::randomToken();
        $params = [
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'redirect_uri' => $this->redirectUri,
            'scope' => $this->scope,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::base64Url(hash('sha256', $codeVerifier, true)),
            'code_challenge_method' => 'S256',
        ];
        if ($prompt !== null) {
            $params['prompt'] = $prompt;
        }
        if ($loginHint !== null && $loginHint !== '') {
            $params['login_hint'] = $loginHint;
        }
        if ($maxAge !== null) {
            $params['max_age'] = (string) $maxAge;
        }
        $url = $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
        return new AuthorizationRequest($url, $state, $nonce, $codeVerifier);
    }

    /**
     * Finishes a redirect sign-in at the redirect URI: checks the response against the values kept for it, exchanges
     * the code and validates the ID token.
     *
     * @param string|array<string, string|list<string>> $query the raw query string ($_SERVER['QUERY_STRING'], which
     *        shows repeated parameters), the callback URL, or a parsed array such as $_GET
     * @param ExpectedTransaction|null $expected what createAuthorizationRequest() returned (->toExpected()), or
     *        fromBrowserSdkCookies() when the browser SDK started the sign-in
     */
    public function handleCallback(string|array $query, ?ExpectedTransaction $expected): SignInResult
    {
        $response = self::readCallbackParams($query);
        if ($expected === null || $expected->state === '' || $expected->nonce === '' || $expected->codeVerifier === '') {
            throw new RanteLoginException('missing_transaction', 'No sign-in is in progress for this browser, or it expired.');
        }
        if ($response['state'] === null || !hash_equals($expected->state, $response['state'])) {
            throw new RanteLoginException('state_mismatch', 'The response does not belong to the sign-in this browser started.');
        }
        if ($response['iss'] !== $this->issuer) { // RFC 9207
            throw new RanteLoginException('issuer_mismatch', 'The response did not come from Rante Login.');
        }
        if ($response['error'] !== null && $response['error'] !== '') {
            $code = preg_match('/^[a-z0-9_]{1,64}$/', $response['error']) === 1 ? $response['error'] : 'authorization_failed';
            $description = self::clean($response['error_description']);
            throw new RanteLoginException($code, $description !== '' ? $description : $code);
        }
        if ($response['code'] === null || $response['code'] === '') {
            throw new RanteLoginException('invalid_request', 'The response has no code.');
        }
        $tokens = $this->exchangeCode($response['code'], $expected->codeVerifier);
        return new SignInResult($this->validateIdToken($tokens->idToken, $expected->nonce), $tokens);
    }

    /** The token request: the code, the PKCE verifier and the app's client authentication. */
    public function exchangeCode(string $code, string $codeVerifier): TokenSet
    {
        if ($code === '' || $codeVerifier === '') {
            throw new RanteLoginException('invalid_request', 'The code and the code verifier are required.');
        }
        $tokenEndpoint = $this->discover()['token_endpoint'];
        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'code_verifier' => $codeVerifier,
        ];
        if ($this->signingKey !== null) {
            $form['client_assertion_type'] = self::ASSERTION_TYPE;
            $form['client_assertion'] = $this->clientAssertion($tokenEndpoint);
        }
        // A browser-only app sends no credential at all: the PKCE verifier is its only proof.
        $response = $this->send('POST', $tokenEndpoint, $form);
        $body = $response->json();
        if ($response->status !== 200) {
            $error = is_string($body['error'] ?? null) && preg_match('/^[a-z0-9_]{1,64}$/', $body['error']) === 1 ? $body['error'] : 'token_request_failed';
            $description = self::clean(is_string($body['error_description'] ?? null) ? $body['error_description'] : null);
            throw new RanteLoginException($error, $description !== '' ? $description : 'The token endpoint answered ' . $response->status . '.', $response->status);
        }
        $idToken = $body['id_token'] ?? null;
        $accessToken = $body['access_token'] ?? null;
        if (!is_string($idToken) || $idToken === '' || !is_string($accessToken) || $accessToken === ''
            || strcasecmp((string) ($body['token_type'] ?? ''), 'Bearer') !== 0) {
            throw new RanteLoginException('invalid_token_response', 'The token response has no ID token or no Bearer access token.');
        }
        return new TokenSet($accessToken, 'Bearer', is_int($body['expires_in'] ?? null) ? $body['expires_in'] : null, $idToken,
            is_string($body['scope'] ?? null) ? $body['scope'] : null);
    }

    /**
     * Validates an ID token before you trust it: the RS256 signature with the key its kid names in Rante Login's
     * JWKS, iss, aud (and azp), exp (with clock skew), iat, sub, and the nonce you expect. Returns its claims.
     */
    public function validateIdToken(?string $idToken, string $nonce): ValidatedIdToken
    {
        if ($nonce === '') {
            throw new RanteLoginException('invalid_request', 'The expected nonce is required.');
        }
        if ($idToken === null || $idToken === '') {
            throw new RanteLoginException('invalid_id_token', 'The ID token is missing.');
        }
        $claims = $this->decode($idToken);
        foreach (['iss', 'sub', 'aud', 'exp', 'iat', 'nonce'] as $name) {
            if (!array_key_exists($name, $claims)) {
                throw new RanteLoginException('invalid_id_token', 'The ID token has no ' . $name . '.');
            }
        }
        if ($claims['iss'] !== $this->issuer) {
            throw new RanteLoginException('invalid_id_token', 'The ID token was issued by someone else (iss).');
        }
        $audiences = is_array($claims['aud']) ? $claims['aud'] : [$claims['aud']];
        if (!in_array($this->clientId, $audiences, true)) {
            throw new RanteLoginException('invalid_id_token', 'The ID token was issued to another app (aud).');
        }
        if (array_key_exists('azp', $claims) ? $claims['azp'] !== $this->clientId : count($audiences) > 1) {
            throw new RanteLoginException('invalid_id_token', 'The ID token was issued to another app (azp).');
        }
        if (!is_string($claims['nonce']) || !hash_equals($nonce, $claims['nonce'])) {
            throw new RanteLoginException('invalid_id_token', 'The ID token was issued for another sign-in (nonce).');
        }
        if (!is_string($claims['sub']) || $claims['sub'] === '') {
            throw new RanteLoginException('invalid_id_token', 'The ID token has no sub.');
        }
        return new ValidatedIdToken($claims['sub'], $claims);
    }

    /**
     * The person's claims from the userinfo endpoint, with the access token from the code exchange (15 minutes).
     * Pass the ID token's sub as $expectedSubject: OpenID Connect requires that both match.
     */
    public function fetchUserInfo(string $accessToken, ?string $expectedSubject = null): UserInfo
    {
        if ($accessToken === '') {
            throw new RanteLoginException('invalid_request', 'An access token is required.');
        }
        $response = $this->send('GET', $this->discover()['userinfo_endpoint'], null, ['Authorization' => 'Bearer ' . $accessToken]);
        if ($response->status === 401) {
            throw new RanteLoginException('invalid_token', 'The access token was refused: it expired, or the person removed their consent.', 401);
        }
        $body = $response->json();
        if ($response->status !== 200 || !is_string($body['sub'] ?? null) || $body['sub'] === '') {
            throw new RanteLoginException('userinfo_failed', 'The userinfo endpoint answered ' . $response->status . '.', $response->status);
        }
        if ($expectedSubject !== null && $body['sub'] !== $expectedSubject) {
            throw new RanteLoginException('userinfo_subject_mismatch', "The userinfo sub is not the ID token's sub.");
        }
        return new UserInfo($body['sub'], $body);
    }

    /**
     * The values the browser SDK (serverSide: true) kept for a redirect sign-in: from $_COOKIE, or the Cookie header.
     * Null when any is missing. Clear the three cookies (BrowserSdkCookies::ALL) once read: each sign-in uses them once.
     *
     * @param string|array<string, mixed> $cookies
     */
    public static function fromBrowserSdkCookies(string|array $cookies): ?ExpectedTransaction
    {
        if (is_string($cookies)) {
            $parsed = [];
            foreach (explode(';', $cookies) as $part) {
                $pair = explode('=', $part, 2);
                if (count($pair) === 2 && !array_key_exists(trim($pair[0]), $parsed)) {
                    $parsed[trim($pair[0])] = trim($pair[1]);
                }
            }
            $cookies = $parsed;
        }
        return ExpectedTransaction::fromArray([
            'state' => $cookies[BrowserSdkCookies::STATE] ?? null,
            'nonce' => $cookies[BrowserSdkCookies::NONCE] ?? null,
            'codeVerifier' => $cookies[BrowserSdkCookies::CODE_VERIFIER] ?? null,
        ]);
    }

    // ---------------------------------------------------------------------------------------------- internals

    /**
     * The discovery document, from the cache or Rante Login.
     *
     * @return array<string, string>
     */
    private function discover(): array
    {
        if ($this->metadata !== null) {
            return $this->metadata;
        }
        $cacheKey = 'rante_login.discovery.' . hash('sha256', $this->issuer);
        $metadata = $this->cache?->get($cacheKey);
        if (!is_array($metadata)) {
            $response = $this->send('GET', $this->issuer . '/.well-known/openid-configuration');
            $metadata = $response->json();
            if ($response->status !== 200 || $metadata === null) {
                throw new RanteLoginException('discovery_failed', 'The discovery document answered ' . $response->status . '.', $response->status);
            }
            if (($metadata['issuer'] ?? null) !== $this->issuer) {
                throw new RanteLoginException('discovery_failed', 'The discovery document names another issuer.');
            }
            foreach (['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'] as $name) {
                if (!is_string($metadata[$name] ?? null) || $metadata[$name] === '') {
                    throw new RanteLoginException('discovery_failed', 'The discovery document has no ' . $name . '.');
                }
            }
            $this->cache?->set($cacheKey, $metadata, 3600);
        }
        return $this->metadata = $metadata;
    }

    /**
     * Verifies the signature (RS256, with the JWKS key the token's kid names) and exp, nbf and iat (with clock skew),
     * and returns the claims. A kid that isn't known yet makes it fetch the keys again (key rotation), at most every
     * 30 seconds.
     *
     * @return array<string, mixed>
     */
    private function decode(string $idToken): array
    {
        $previousLeeway = JWT::$leeway;
        JWT::$leeway = $this->clockSkew;
        try {
            for ($attempt = 0; ; $attempt++) {
                $keys = JWK::parseKeySet($this->signingKeys($attempt > 0), 'RS256');
                try {
                    return json_decode((string) json_encode(JWT::decode($idToken, $keys)), true, 512, JSON_THROW_ON_ERROR);
                } catch (\UnexpectedValueException $error) {
                    $unknownKid = str_contains($error->getMessage(), '"kid" invalid');
                    if (!$unknownKid || $attempt > 0 || time() - $this->jwksFetchedAt < self::JWKS_COOLDOWN) {
                        throw $error;
                    }
                }
            }
        } catch (RanteLoginException $error) {
            throw $error;
        } catch (\Throwable $error) {
            throw new RanteLoginException('invalid_id_token', 'The ID token failed validation (' . (new \ReflectionClass($error))->getShortName() . ': '
                . self::clean($error->getMessage()) . ').', null, $error);
        } finally {
            JWT::$leeway = $previousLeeway;
        }
    }

    /** @return array<string, mixed> the JWKS, from the cache or Rante Login */
    private function signingKeys(bool $refresh): array
    {
        $cacheKey = 'rante_login.jwks.' . hash('sha256', $this->issuer);
        if (!$refresh && $this->jwks === null) {
            $cached = $this->cache?->get($cacheKey);
            if (is_array($cached) && is_array($cached['jwks'] ?? null)) {
                $this->jwks = $cached['jwks'];
                $this->jwksFetchedAt = (int) ($cached['fetchedAt'] ?? 0);
            }
        }
        if ($refresh || $this->jwks === null) {
            $response = $this->send('GET', $this->discover()['jwks_uri']);
            $jwks = $response->json();
            if ($response->status !== 200 || !is_array($jwks['keys'] ?? null)) {
                throw new RanteLoginException('network_error', "Rante Login's signing keys could not be fetched.", $response->status);
            }
            $this->jwks = $jwks;
            $this->jwksFetchedAt = time();
            $this->cache?->set($cacheKey, ['jwks' => $jwks, 'fetchedAt' => $this->jwksFetchedAt], 600);
        }
        return $this->jwks;
    }

    // private_key_jwt (RFC 7523): a short-lived JWT signed with the app's private key. iss and sub are the client ID,
    // aud the token endpoint, the kid the Signed JWT key's prefix, and the jti unique (Rante Login accepts it once).
    private function clientAssertion(string $tokenEndpoint): string
    {
        $now = time();
        return JWT::encode([
            'iss' => $this->clientId,
            'sub' => $this->clientId,
            'aud' => $tokenEndpoint,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + self::ASSERTION_LIFETIME,
            'jti' => self::randomToken(),
        ], $this->signingKey->privateKey(), $this->signingKey->algorithm, $this->signingKey->keyPrefix);
    }

    /**
     * @param array<string, string>|null $form
     * @param array<string, string> $headers
     */
    private function send(string $method, string $url, ?array $form = null, array $headers = []): HttpResponse
    {
        try {
            return $this->http->send($method, $url, ['Accept' => 'application/json'] + $headers, $form);
        } catch (\RuntimeException $error) {
            throw new RanteLoginException('network_error', 'Rante Login could not be reached.', null, $error);
        }
    }

    /**
     * The redirect's parameters. A repeated parameter is refused rather than guessed.
     *
     * @param string|array<string, mixed> $query
     * @return array{code: ?string, state: ?string, iss: ?string, error: ?string, error_description: ?string}
     */
    private static function readCallbackParams(string|array $query): array
    {
        $values = [];
        if (is_string($query)) {
            if (preg_match('/^[A-Za-z][A-Za-z0-9+.-]*:/', $query) === 1) {
                $query = (string) parse_url($query, PHP_URL_QUERY);
            }
            foreach (explode('&', ltrim($query, '?')) as $pair) {
                if ($pair === '') {
                    continue;
                }
                [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
                $values[urldecode($name)][] = urldecode($value);
            }
        } else {
            foreach ($query as $name => $value) {
                $values[(string) $name] = is_array($value) ? array_values($value) : [$value];
            }
        }
        $out = [];
        foreach (['code', 'state', 'iss', 'error', 'error_description'] as $name) {
            $found = $values[$name] ?? [];
            if (count($found) > 1) {
                throw new RanteLoginException('invalid_request', 'The response repeats ' . $name . '.');
            }
            $out[$name] = isset($found[0]) && is_string($found[0]) ? $found[0] : null;
        }
        return $out;
    }

    private static function normalizeClientId(string $value): string
    {
        $clientId = strtolower(trim($value));
        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $clientId) !== 1) {
            throw new RanteLoginException('invalid_configuration', "clientId must be the app's Application (client) ID from the Rante Portal.");
        }
        return $clientId;
    }

    // Rante Login matches redirect URIs exactly, and stores them with the scheme and host in lower case.
    private static function normalizeRedirectUri(string $value): string
    {
        $uri = (string) preg_replace_callback('/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\/?#]*/', fn (array $m) => strtolower($m[0]), trim($value));
        $parts = parse_url($uri);
        $loopback = in_array($parts['host'] ?? '', ['localhost', '127.0.0.1'], true);
        if ($parts === false || !isset($parts['scheme'], $parts['host']) || str_contains($uri, '#') || isset($parts['user']) || strlen($uri) > 512
            || !($parts['scheme'] === 'https' || ($parts['scheme'] === 'http' && $loopback))) {
            throw new RanteLoginException('invalid_configuration',
                'redirectUri must be the absolute https URI registered on the app (http only for localhost or 127.0.0.1), without a fragment.');
        }
        return $uri;
    }

    private static function normalizeScope(string $value): string
    {
        $parts = preg_split('/\s+/', trim($value), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        if (!in_array('openid', $parts, true) || array_diff($parts, self::SCOPES) !== []) {
            throw new RanteLoginException('invalid_configuration', 'scope must include openid and only these scopes: ' . implode(', ', self::SCOPES) . '.');
        }
        return implode(' ', array_values(array_unique($parts)));
    }

    private static function normalizeIssuer(string $value): string
    {
        $parts = parse_url($value);
        $loopback = in_array($parts['host'] ?? '', ['localhost', '127.0.0.1'], true);
        if ($parts === false || isset($parts['query']) || isset($parts['fragment'])
            || !(($parts['scheme'] ?? '') === 'https' || (($parts['scheme'] ?? '') === 'http' && $loopback))) {
            throw new RanteLoginException('invalid_configuration', 'issuer must be an https URL.');
        }
        return rtrim($value, '/');
    }

    private static function checkPrompt(?string $prompt): ?string
    {
        if ($prompt === null || $prompt === '') {
            return null;
        }
        $parts = preg_split('/\s+/', trim($prompt), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        if ($parts === [] || array_diff($parts, self::PROMPTS) !== [] || (in_array('none', $parts, true) && count($parts) > 1)) {
            throw new RanteLoginException('invalid_request', 'prompt must be ' . implode(', ', self::PROMPTS) . ' (none alone).');
        }
        return implode(' ', $parts);
    }

    private static function randomToken(): string
    {
        return self::base64Url(random_bytes(32));
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function clean(?string $value): string
    {
        return $value === null ? '' : substr((string) preg_replace('/[\x00-\x1f\x7f]/', ' ', $value), 0, 300);
    }
}
