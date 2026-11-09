<?php

declare(strict_types=1);

namespace Rante\Login\Tests;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Rante\Login\AuthorizationRequest;
use Rante\Login\BrowserSdkCookies;
use Rante\Login\ExpectedTransaction;
use Rante\Login\RanteLoginClient;
use Rante\Login\RanteLoginException;
use Rante\Login\SigningKey;

final class RanteLoginClientTest extends TestCase
{
    private const WEB_CLIENT = '11111111-2222-4333-8444-555555555555';
    private const BROWSER_CLIENT = '66666666-7777-4888-9999-aaaaaaaaaaaa';
    // The fake key prefixes, split so secret scanners don't take them for Stripe restricted keys (rk_live_ + 24 characters).
    private const RSA_PREFIX = 'rk_live_' . '0123456789abcdef01234567';
    private const EC_PREFIX = 'rk_live_' . '89abcdef0123456789abcdef';
    private const REDIRECT_URI = 'http://localhost:3000/auth/rante/callback';
    private const NONCE = 'expected-nonce';

    private LocalIdp $idp;
    private string $rsaPem;
    private string $ecPem;

    /** Generated once for the class: RSA key generation is slow. @var array<string, mixed> */
    private static array $keys = [];

    public static function setUpBeforeClass(): void
    {
        $rsa = Keys::rsa();
        $ec = Keys::ec();
        self::$keys = ['rsa' => $rsa, 'ec' => $ec, 'idp' => Keys::rsa(), 'rsaPem' => Keys::privatePem($rsa), 'ecPem' => Keys::privatePem($ec)];
    }

    protected function setUp(): void
    {
        $this->rsaPem = self::$keys['rsaPem'];
        $this->ecPem = self::$keys['ecPem'];
        $this->idp = new LocalIdp(self::$keys['idp']);
        $this->idp->registerClient(self::WEB_CLIENT, 'Web', [
            self::RSA_PREFIX => Keys::publicPem(self::$keys['rsa']),
            self::EC_PREFIX => Keys::publicPem(self::$keys['ec']),
        ]);
        $this->idp->registerClient(self::BROWSER_CLIENT, 'BrowserOnly');
    }

    private function client(string $clientId = self::WEB_CLIENT, ?SigningKey $key = null, bool $browserOnly = false, ?ArrayCache $cache = null): RanteLoginClient
    {
        return new RanteLoginClient($clientId, self::REDIRECT_URI,
            signingKey: $browserOnly ? null : ($key ?? SigningKey::fromPem(self::RSA_PREFIX, $this->rsaPem)),
            issuer: LocalIdp::ISSUER, http: $this->idp, cache: $cache);
    }

    /** The authorize step, as the test IdP sees it: a code bound to the request's PKCE challenge and nonce. */
    private function authorize(AuthorizationRequest $request, string $clientId = self::WEB_CLIENT): string
    {
        parse_str((string) parse_url($request->url, PHP_URL_QUERY), $query);
        return $this->idp->issueCode($clientId, $query['redirect_uri'], $query['code_challenge'], $query['nonce'],
            ['sub' => 'pairwise-subject-1', 'name' => 'Test Person']);
    }

    private static function callbackQuery(?string $code, ?string $state, ?string $iss = LocalIdp::ISSUER): string
    {
        return http_build_query(array_filter(['code' => $code, 'state' => $state, 'iss' => $iss], static fn ($v) => $v !== null), '', '&', PHP_QUERY_RFC3986);
    }

    private function fails(string $code, callable $call): RanteLoginException
    {
        try {
            $call();
        } catch (RanteLoginException $error) {
            self::assertSame($code, $error->errorCode, $error->getMessage());
            return $error;
        }
        self::fail("Expected a RanteLoginException with code $code.");
    }

    /** @return array<string, string> */
    private function lastTokenForm(): array
    {
        $tokens = array_values(array_filter($this->idp->requests, static fn ($r) => str_ends_with($r['url'], '/token')));
        return $tokens[count($tokens) - 1]['form'];
    }

    public function testCreateAuthorizationRequestBuildsTheUrlWithPkceS256StateAndNonce(): void
    {
        $request = $this->client()->createAuthorizationRequest();
        self::assertStringStartsWith(LocalIdp::AUTHORIZATION_ENDPOINT . '?', $request->url);
        parse_str((string) parse_url($request->url, PHP_URL_QUERY), $query);
        $names = array_keys($query);
        sort($names);
        self::assertSame(['client_id', 'code_challenge', 'code_challenge_method', 'nonce', 'redirect_uri', 'response_type', 'scope', 'state'], $names);
        self::assertSame(self::WEB_CLIENT, $query['client_id']);
        self::assertSame('code', $query['response_type']);
        self::assertSame(self::REDIRECT_URI, $query['redirect_uri']);
        self::assertSame('openid profile email', $query['scope']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertSame(rtrim(strtr(base64_encode(hash('sha256', $request->codeVerifier, true)), '+/', '-_'), '='), $query['code_challenge']);
        self::assertSame($request->state, $query['state']);
        self::assertSame($request->nonce, $query['nonce']);
        self::assertSame(43, strlen($request->codeVerifier));
        $other = $this->client()->createAuthorizationRequest();
        self::assertNotSame($request->state, $other->state);
        self::assertNotSame($request->nonce, $other->nonce);
        self::assertNotSame($request->codeVerifier, $other->codeVerifier);
    }

    public function testCreateAuthorizationRequestPassesOptionsAndRefusesBadOnes(): void
    {
        $client = $this->client();
        $request = $client->createAuthorizationRequest(nonce: 'server-nonce-1', prompt: 'login', loginHint: 'person@example.com', maxAge: 0);
        parse_str((string) parse_url($request->url, PHP_URL_QUERY), $query);
        self::assertSame('server-nonce-1', $request->nonce);
        self::assertSame('server-nonce-1', $query['nonce']);
        self::assertSame('login', $query['prompt']);
        self::assertSame('person@example.com', $query['login_hint']);
        self::assertSame('0', $query['max_age']);
        $this->fails('invalid_request', fn () => $client->createAuthorizationRequest(nonce: 'has space'));
        $this->fails('invalid_request', fn () => $client->createAuthorizationRequest(prompt: 'none login'));
        $this->fails('invalid_request', fn () => $client->createAuthorizationRequest(prompt: 'always'));
        $this->fails('invalid_request', fn () => $client->createAuthorizationRequest(maxAge: -1));
    }

    public function testServerSideWebsiteSignsInWithAPrivateKeyJwtRs256Assertion(): void
    {
        $client = $this->client();
        self::assertSame('private_key_jwt', $client->clientAuthentication());
        $request = $client->createAuthorizationRequest();
        $result = $client->handleCallback(self::REDIRECT_URI . '?' . self::callbackQuery($this->authorize($request), $request->state), $request->toExpected());
        self::assertSame('pairwise-subject-1', $result->subject());
        self::assertSame('Test Person', $result->claims()['name']);
        self::assertSame($request->nonce, $result->claims()['nonce']);
        self::assertSame('Bearer', $result->tokens->tokenType);
        self::assertSame(900, $result->tokens->expiresIn);
        self::assertNotSame('', $result->accessToken());

        $form = $this->lastTokenForm();
        self::assertSame('authorization_code', $form['grant_type']);
        self::assertSame(self::REDIRECT_URI, $form['redirect_uri']);
        self::assertSame(self::WEB_CLIENT, $form['client_id']);
        self::assertSame($request->codeVerifier, $form['code_verifier']);
        self::assertSame('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $form['client_assertion_type']);
        ['header' => $header, 'payload' => $payload] = $this->idp->lastAssertion;
        self::assertSame('RS256', $header['alg']);
        self::assertSame(self::RSA_PREFIX, $header['kid']);
        self::assertSame(self::WEB_CLIENT, $payload['iss']);
        self::assertSame(self::WEB_CLIENT, $payload['sub']);
        self::assertSame(LocalIdp::TOKEN_ENDPOINT, $payload['aud']);
        self::assertLessThanOrEqual(300, $payload['exp'] - $payload['iat']);
        self::assertNotEmpty($payload['jti']);
    }

    public function testEs256KeysSignEs256Assertions(): void
    {
        $client = $this->client(key: SigningKey::fromPem(self::EC_PREFIX, $this->ecPem));
        $request = $client->createAuthorizationRequest();
        $result = $client->handleCallback(self::callbackQuery($this->authorize($request), $request->state), $request->toExpected());
        self::assertSame('pairwise-subject-1', $result->subject());
        self::assertSame('ES256', $this->idp->lastAssertion['header']['alg']);
        self::assertSame(self::EC_PREFIX, $this->idp->lastAssertion['header']['kid']);
    }

    public function testBrowserOnlyWebsiteSendsNoClientCredential(): void
    {
        $client = $this->client(self::BROWSER_CLIENT, browserOnly: true);
        self::assertSame('none', $client->clientAuthentication());
        $request = $client->createAuthorizationRequest();
        $query = ['code' => $this->authorize($request, self::BROWSER_CLIENT), 'state' => $request->state, 'iss' => LocalIdp::ISSUER];
        $result = $client->handleCallback($query, new ExpectedTransaction($request->state, $request->nonce, $request->codeVerifier));
        self::assertSame(self::BROWSER_CLIENT, $result->claims()['aud']);
        $form = $this->lastTokenForm();
        self::assertArrayNotHasKey('client_assertion', $form);
        self::assertArrayNotHasKey('client_assertion_type', $form);
        self::assertArrayNotHasKey('client_secret', $form);
    }

    public function testRefusesBadResponsesBeforeAnyTokenRequest(): void
    {
        $client = $this->client();
        $request = $client->createAuthorizationRequest();
        $code = $this->authorize($request);
        $before = count($this->idp->requests);
        $this->fails('state_mismatch', fn () => $client->handleCallback(self::callbackQuery($code, 'another'), $request->toExpected()));
        $this->fails('issuer_mismatch', fn () => $client->handleCallback(self::callbackQuery($code, $request->state, null), $request->toExpected()));
        $this->fails('issuer_mismatch', fn () => $client->handleCallback(self::callbackQuery($code, $request->state, 'https://login.example.com/common/v2.0'), $request->toExpected()));
        $this->fails('invalid_request', fn () => $client->handleCallback(self::callbackQuery($code, $request->state) . '&state=' . $request->state, $request->toExpected()));
        $this->fails('missing_transaction', fn () => $client->handleCallback(self::callbackQuery($code, $request->state), null));
        $this->fails('invalid_request', fn () => $client->handleCallback(self::callbackQuery(null, $request->state), $request->toExpected()));
        self::assertNull(ExpectedTransaction::fromArray(['state' => $request->state]));
        self::assertCount($before, $this->idp->requests);
    }

    public function testReportsTheProvidersError(): void
    {
        $client = $this->client();
        $request = $client->createAuthorizationRequest();
        $error = $this->fails('access_denied', fn () => $client->handleCallback(['error' => 'access_denied', 'error_description' => 'The person cancelled the sign-in.',
            'state' => $request->state, 'iss' => LocalIdp::ISSUER], $request->toExpected()));
        self::assertSame('The person cancelled the sign-in.', $error->getMessage());
    }

    public function testTokenEndpointErrorsKeepTheirCodeAndStatus(): void
    {
        $client = $this->client();
        $request = $client->createAuthorizationRequest();
        $query = self::callbackQuery($this->authorize($request), $request->state);
        $client->handleCallback($query, $request->toExpected());
        self::assertSame(400, $this->fails('invalid_grant', fn () => $client->handleCallback($query, $request->toExpected()))->status);
    }

    public function testAKeyThatIsNotLinkedToTheAppGetsInvalidClient(): void
    {
        $otherPem = Keys::privatePem(Keys::rsa());
        $client = $this->client(key: SigningKey::fromPem('rk_live_' . str_repeat('f', 24), $otherPem));
        $request = $client->createAuthorizationRequest();
        self::assertSame(401, $this->fails('invalid_client', fn () => $client->handleCallback(self::callbackQuery($this->authorize($request), $request->state), $request->toExpected()))->status);
    }

    /** @param array<string, mixed> $overrides */
    private function valid(array $overrides = []): string
    {
        return $this->idp->mintIdToken(array_merge(['aud' => self::WEB_CLIENT, 'azp' => self::WEB_CLIENT, 'nonce' => self::NONCE], $overrides));
    }

    public function testValidateIdTokenAcceptsAValidToken(): void
    {
        $token = $this->client()->validateIdToken($this->valid(['name' => 'Test Person']), self::NONCE);
        self::assertSame('pairwise-subject-1', $token->subject);
        self::assertSame('Test Person', $token->claims['name']);
    }

    public function testValidateIdTokenRefusesTokensThatFailAnyCheck(): void
    {
        $client = $this->client();
        $now = time();
        $stranger = Keys::rsa();
        $body = ['iss' => LocalIdp::ISSUER, 'sub' => 's', 'aud' => self::WEB_CLIENT, 'azp' => self::WEB_CLIENT, 'iat' => $now, 'exp' => $now + 600, 'nonce' => self::NONCE];
        $b64 = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
        $cases = [
            'another key, same kid' => $this->idp->mintIdToken(['aud' => self::WEB_CLIENT, 'nonce' => self::NONCE], $stranger, 'test-key-1'),
            'unknown kid' => $this->idp->mintIdToken(['aud' => self::WEB_CLIENT, 'nonce' => self::NONCE], $stranger, 'not-a-rante-key'),
            'another issuer' => $this->valid(['iss' => 'https://login.example.com/common/v2.0']),
            'another audience' => $this->valid(['aud' => '99999999-2222-4333-8444-555555555555', 'azp' => null]),
            'another azp' => $this->valid(['azp' => '99999999-2222-4333-8444-555555555555']),
            'expired' => $this->valid(['iat' => $now - 1200, 'exp' => $now - 600]),
            'another nonce' => $this->valid(['nonce' => 'other-nonce']),
            'no nonce' => $this->valid(['nonce' => null]),
            'no sub' => $this->valid(['sub' => null]),
            'no exp' => $this->valid(['exp' => null]),
            'HS256' => JWT::encode($body, str_repeat('s', 32), 'HS256', 'test-key-1'),
            'alg none' => $b64('{"alg":"none","typ":"JWT"}') . '.' . $b64((string) json_encode($body)) . '.',
            'not a JWT' => 'not-a-jwt',
        ];
        foreach ($cases as $name => $token) {
            try {
                $client->validateIdToken($token, self::NONCE);
                self::fail("$name was accepted");
            } catch (RanteLoginException $error) {
                self::assertSame('invalid_id_token', $error->errorCode, "$name: {$error->getMessage()}");
            }
        }
        $this->fails('invalid_request', fn () => $client->validateIdToken($this->valid(), ''));
    }

    public function testValidateIdTokenAllowsAMinuteOfClockSkew(): void
    {
        $now = time();
        self::assertSame('pairwise-subject-1', $this->client()->validateIdToken($this->valid(['iat' => $now - 630, 'exp' => $now - 30]), self::NONCE)->subject);
    }

    public function testValidateIdTokenUsesAKeyThatRanteLoginAddsLater(): void
    {
        $added = $this->idp->addSigningKey('test-key-2');
        $token = $this->idp->mintIdToken(['aud' => self::WEB_CLIENT, 'nonce' => self::NONCE], $added, 'test-key-2');
        self::assertSame('pairwise-subject-1', $this->client()->validateIdToken($token, self::NONCE)->subject);
    }

    public function testACacheKeepsDiscoveryAndKeysBetweenRequests(): void
    {
        $cache = new ArrayCache();
        $this->client(cache: $cache)->validateIdToken($this->valid(), self::NONCE);
        $fetches = count($this->idp->requests);
        $this->client(cache: $cache)->validateIdToken($this->valid(), self::NONCE); // a new client, as on the next PHP request
        self::assertCount($fetches, $this->idp->requests);
        self::assertCount(2, $cache->items);
    }

    public function testFetchUserInfoReturnsTheClaimsAndChecksTheSub(): void
    {
        $client = $this->client();
        $request = $client->createAuthorizationRequest();
        $result = $client->handleCallback(self::callbackQuery($this->authorize($request), $request->state), $request->toExpected());
        $userinfo = $client->fetchUserInfo($result->accessToken(), $result->subject());
        self::assertSame('pairwise-subject-1', $userinfo->subject);
        self::assertSame('Test Person', $userinfo->claims['name']);
        $calls = array_values(array_filter($this->idp->requests, static fn ($r) => str_ends_with($r['url'], '/userinfo')));
        self::assertSame('Bearer ' . $result->accessToken(), $calls[count($calls) - 1]['headers']['Authorization']);
        $this->fails('userinfo_subject_mismatch', fn () => $client->fetchUserInfo($result->accessToken(), 'someone-else'));
        self::assertSame(401, $this->fails('invalid_token', fn () => $client->fetchUserInfo('expired-or-unknown'))->status);
    }

    public function testFromBrowserSdkCookiesReadsTheThreeCookies(): void
    {
        $verifier = str_repeat('v', 43);
        $expected = new ExpectedTransaction('s1', 'n1', $verifier);
        self::assertEquals($expected, RanteLoginClient::fromBrowserSdkCookies([BrowserSdkCookies::STATE => 's1', BrowserSdkCookies::NONCE => 'n1', BrowserSdkCookies::CODE_VERIFIER => $verifier]));
        self::assertEquals($expected, RanteLoginClient::fromBrowserSdkCookies("other=1; rante_login_pkce=$verifier; rante_login_state=s1; rante_login_nonce=n1"));
        self::assertNull(RanteLoginClient::fromBrowserSdkCookies([BrowserSdkCookies::STATE => 's1']));
        self::assertNull(RanteLoginClient::fromBrowserSdkCookies(''));
    }

    public function testConfigurationRefusesBadSettings(): void
    {
        $weakPem = Keys::privatePem(Keys::rsa(1024));
        $p384Pem = Keys::privatePem(Keys::ec('secp384r1'));
        $publicPem = openssl_pkey_get_details(openssl_pkey_get_private($this->rsaPem))['key'];
        $bad = [
            'client ID' => fn () => new RanteLoginClient('my-app', self::REDIRECT_URI),
            'http redirect URI' => fn () => new RanteLoginClient(self::WEB_CLIENT, 'http://shop.example.com/callback'),
            'redirect URI with a fragment' => fn () => new RanteLoginClient(self::WEB_CLIENT, 'https://shop.example.com/callback#x'),
            'scope without openid' => fn () => new RanteLoginClient(self::WEB_CLIENT, self::REDIRECT_URI, scope: 'profile email'),
            'unknown scope' => fn () => new RanteLoginClient(self::WEB_CLIENT, self::REDIRECT_URI, scope: 'openid offline_access'),
            'http issuer' => fn () => new RanteLoginClient(self::WEB_CLIENT, self::REDIRECT_URI, issuer: 'http://login.example.com/common/v2.0'),
            'key prefix' => fn () => SigningKey::fromPem('my-key', $this->rsaPem),
            'RSA 1024' => fn () => SigningKey::fromPem(self::RSA_PREFIX, $weakPem),
            'EC P-384' => fn () => SigningKey::fromPem(self::RSA_PREFIX, $p384Pem),
            'a public key' => fn () => SigningKey::fromPem(self::RSA_PREFIX, $publicPem),
        ];
        foreach ($bad as $name => $create) {
            try {
                $create();
                self::fail("$name was accepted");
            } catch (RanteLoginException $error) {
                self::assertSame('invalid_configuration', $error->errorCode, $name);
            }
        }
    }

    public function testConfigurationReadsPemKeysAndNormalizesLikeTheBrowserSdk(): void
    {
        self::assertSame('RS256', SigningKey::fromPem(self::RSA_PREFIX, $this->rsaPem)->algorithm);
        self::assertSame('ES256', SigningKey::fromPem(self::EC_PREFIX, $this->ecPem)->algorithm);
        $client = new RanteLoginClient(strtoupper(self::WEB_CLIENT), 'HTTPS://Shop.Example.com/Auth/Callback');
        self::assertSame(self::WEB_CLIENT, $client->clientId);
        self::assertSame('https://shop.example.com/Auth/Callback', $client->redirectUri);
        self::assertSame('https://login.rante.com/common/v2.0', $client->issuer);
    }

    public function testDiscoveryThatNamesAnotherIssuerIsRefused(): void
    {
        $this->idp->discoveryIssuer = 'https://login.example.com/common/v2.0';
        $this->fails('discovery_failed', fn () => $this->client()->createAuthorizationRequest());
    }

    public function testAnUnreachableProviderIsANetworkError(): void
    {
        $this->idp->unreachable = true;
        $this->fails('network_error', fn () => $this->client()->createAuthorizationRequest());
    }
}
