<?php

declare(strict_types=1);

namespace Rante\Login\Tests;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Rante\Login\Http\HttpClient;
use Rante\Login\Http\HttpResponse;

/**
 * A local OpenID provider for the tests, shaped like Rante Login, answering in process (no network): discovery, JWKS,
 * token and userinfo. It issues codes that the tests hand it (standing in for the authorize step), checks each token
 * request (client_id, PKCE, redirect URI, client authentication, single-use assertions) and signs ID tokens with a key
 * generated for the run.
 */
final class LocalIdp implements HttpClient
{
    public const ORIGIN = 'https://idp.test';
    public const ISSUER = self::ORIGIN . '/common/v2.0';
    public const AUTHORIZATION_ENDPOINT = self::ORIGIN . '/common/oauth2/v2.0/authorize';
    public const TOKEN_ENDPOINT = self::ORIGIN . '/common/oauth2/v2.0/token';
    private const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    public string $discoveryIssuer = self::ISSUER;
    /** @var list<array{kid: string, private: \OpenSSLAsymmetricKey, jwk: array<string, string>}> */
    public array $signingKeys = [];
    /** @var list<array{method: string, url: string, headers: array<string, string>, form: ?array<string, string>}> */
    public array $requests = [];
    /** @var array{header: array<string, mixed>, payload: array<string, mixed>}|null */
    public ?array $lastAssertion = null;
    public bool $unreachable = false;

    /** @var array<string, array{type: string, keys: array<string, string>}> */
    private array $clients = [];
    /** @var array<string, array<string, mixed>> */
    private array $codes = [];
    /** @var array<string, array<string, mixed>> */
    private array $accessTokens = [];
    /** @var array<string, true> */
    private array $usedAssertions = [];

    /** @param \OpenSSLAsymmetricKey|null $signingKey the IdP's first signing key; default a new one */
    public function __construct(?\OpenSSLAsymmetricKey $signingKey = null)
    {
        $this->addSigningKey('test-key-1', $signingKey);
    }

    public function addSigningKey(string $kid, ?\OpenSSLAsymmetricKey $private = null): \OpenSSLAsymmetricKey
    {
        $private ??= Keys::rsa();
        $rsa = openssl_pkey_get_details($private)['rsa'];
        $b64 = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
        $this->signingKeys[] = ['kid' => $kid, 'private' => $private,
            'jwk' => ['kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => $kid, 'n' => $b64($rsa['n']), 'e' => $b64($rsa['e'])]];
        return $private;
    }

    /** @param array<string, string> $keys key prefix => public key PEM */
    public function registerClient(string $clientId, string $type, array $keys = []): void
    {
        $this->clients[$clientId] = ['type' => $type, 'keys' => $keys];
    }

    /** Stands in for the authorize step: a code for these values. @param array<string, mixed> $claims */
    public function issueCode(string $clientId, string $redirectUri, string $codeChallenge, string $nonce, array $claims): string
    {
        $code = bin2hex(random_bytes(32));
        $this->codes[$code] = compact('clientId', 'redirectUri', 'codeChallenge', 'nonce', 'claims');
        return $code;
    }

    /**
     * An ID token like Rante Login's. Override any claim (null removes it), or sign with another key and kid.
     *
     * @param array<string, mixed> $claims
     */
    public function mintIdToken(array $claims, ?\OpenSSLAsymmetricKey $key = null, ?string $kid = null): string
    {
        $now = time();
        $payload = array_filter(array_merge(['iss' => self::ISSUER, 'sub' => 'pairwise-subject-1', 'iat' => $now, 'exp' => $now + 600, 'auth_time' => $now], $claims),
            static fn ($value) => $value !== null);
        return JWT::encode($payload, $key ?? $this->signingKeys[0]['private'], 'RS256', $kid ?? $this->signingKeys[0]['kid']);
    }

    public function send(string $method, string $url, array $headers, ?array $form = null): HttpResponse
    {
        if ($this->unreachable) {
            throw new \RuntimeException('Connection refused');
        }
        $this->requests[] = compact('method', 'url', 'headers', 'form');
        $path = (string) parse_url($url, PHP_URL_PATH);
        return match ("$method $path") {
            'GET /common/v2.0/.well-known/openid-configuration' => $this->json(200, [
                'issuer' => $this->discoveryIssuer,
                'authorization_endpoint' => self::AUTHORIZATION_ENDPOINT,
                'token_endpoint' => self::TOKEN_ENDPOINT,
                'userinfo_endpoint' => self::ORIGIN . '/common/oidc/v2.0/userinfo',
                'jwks_uri' => self::ORIGIN . '/common/discovery/v2.0/keys',
                'response_types_supported' => ['code'],
                'id_token_signing_alg_values_supported' => ['RS256'],
                'token_endpoint_auth_methods_supported' => ['private_key_jwt', 'none'],
                'code_challenge_methods_supported' => ['S256'],
                'authorization_response_iss_parameter_supported' => true,
            ]),
            'GET /common/discovery/v2.0/keys' => $this->json(200, ['keys' => array_map(static fn ($key) => $key['jwk'], $this->signingKeys)]),
            'POST /common/oauth2/v2.0/token' => $this->token($form ?? [], $headers),
            'GET /common/oidc/v2.0/userinfo' => $this->userinfo($headers),
            default => $this->json(404, []),
        };
    }

    /** @param array<string, string> $form @param array<string, string> $headers */
    private function token(array $form, array $headers): HttpResponse
    {
        $refuse = fn (int $status, string $error) => $this->json($status, ['error' => $error, 'error_description' => "test IdP: $error"]);
        $clientId = $form['client_id'] ?? '';
        $client = $this->clients[$clientId] ?? null;
        if ($client === null || isset($form['client_secret']) || isset($headers['Authorization'])) {
            return $refuse(401, 'invalid_client');
        }
        if ($client['type'] === 'Web') {
            $assertion = $form['client_assertion'] ?? '';
            if (($form['client_assertion_type'] ?? '') !== self::ASSERTION_TYPE || $assertion === '') {
                return $refuse(401, 'invalid_client');
            }
            $header = json_decode((string) JWT::urlsafeB64Decode(explode('.', $assertion)[0]), true);
            $publicKey = $client['keys'][$header['kid'] ?? ''] ?? null;
            if ($publicKey === null) {
                return $refuse(401, 'invalid_client');
            }
            try {
                $payload = (array) JWT::decode($assertion, new Key($publicKey, (string) $header['alg']));
            } catch (\Throwable) {
                return $refuse(401, 'invalid_client');
            }
            if (($payload['iss'] ?? null) !== $clientId || ($payload['sub'] ?? null) !== $clientId || ($payload['aud'] ?? null) !== self::TOKEN_ENDPOINT
                || !isset($payload['jti'], $payload['exp'], $payload['iat']) || $payload['exp'] - $payload['iat'] > 300
                || isset($this->usedAssertions[$payload['jti']])) {
                return $refuse(401, 'invalid_client');
            }
            $this->usedAssertions[$payload['jti']] = true;
            $this->lastAssertion = ['header' => $header, 'payload' => $payload];
        } elseif (isset($form['client_assertion']) || isset($form['client_assertion_type'])) {
            return $refuse(401, 'invalid_client');
        }
        $issued = $this->codes[$form['code'] ?? ''] ?? null;
        unset($this->codes[$form['code'] ?? '']);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $form['code_verifier'] ?? '', true)), '+/', '-_'), '=');
        if ($issued === null || $issued['clientId'] !== $clientId || $issued['redirectUri'] !== ($form['redirect_uri'] ?? null)
            || $issued['codeChallenge'] !== $challenge) {
            return $refuse(400, 'invalid_grant');
        }
        $accessToken = bin2hex(random_bytes(16));
        $this->accessTokens[$accessToken] = ['sub' => $issued['claims']['sub'], 'name' => $issued['claims']['name']];
        return $this->json(200, [
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 900,
            'id_token' => $this->mintIdToken(['aud' => $clientId, 'azp' => $clientId, 'nonce' => $issued['nonce']] + $issued['claims']),
            'scope' => 'openid profile email',
        ]);
    }

    /** @param array<string, string> $headers */
    private function userinfo(array $headers): HttpResponse
    {
        $authorization = $headers['Authorization'] ?? '';
        $claims = str_starts_with($authorization, 'Bearer ') ? ($this->accessTokens[substr($authorization, 7)] ?? null) : null;
        return $claims === null ? $this->json(401, []) : $this->json(200, $claims);
    }

    /** @param array<mixed> $body */
    private function json(int $status, array $body): HttpResponse
    {
        return new HttpResponse($status, (string) json_encode($body === [] ? new \stdClass() : $body));
    }
}
