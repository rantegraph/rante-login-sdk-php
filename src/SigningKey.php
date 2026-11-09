<?php

declare(strict_types=1);

namespace Rante\Login;

/**
 * A Signed JWT key linked to the app: its prefix as the Rante Portal shows it (sent as the client assertion's kid)
 * and its private key, RSA of at least 2048 bits (RS256) or EC P-256 (ES256).
 */
final class SigningKey
{
    private function __construct(
        public readonly string $keyPrefix,
        public readonly string $algorithm,
        private readonly \OpenSSLAsymmetricKey $privateKey,
    ) {
    }

    /** From an unencrypted PEM private key (PKCS#8 as openssl genpkey writes it, or the RSA and EC forms). */
    public static function fromPem(string $keyPrefix, string $pem): self
    {
        if (preg_match('/^rk_live_[0-9a-f]{24}$/', $keyPrefix) !== 1) {
            throw new RanteLoginException('invalid_configuration', 'The key prefix must be the one the Rante Portal shows: rk_live_ and 24 hex digits.');
        }
        if (!str_contains($pem, 'PRIVATE KEY-----') || str_contains($pem, 'ENCRYPTED PRIVATE KEY')) {
            throw new RanteLoginException('invalid_configuration', 'The signing key must be an unencrypted PEM private key (-----BEGIN PRIVATE KEY-----).');
        }
        $key = openssl_pkey_get_private($pem);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($key === false || $details === false) {
            throw new RanteLoginException('invalid_configuration', 'The signing key could not be read.');
        }
        if ($details['type'] === OPENSSL_KEYTYPE_RSA) {
            if ($details['bits'] < 2048) {
                throw new RanteLoginException('invalid_configuration', 'RSA signing keys must have at least 2048 bits.');
            }
            return new self($keyPrefix, 'RS256', $key);
        }
        if ($details['type'] === OPENSSL_KEYTYPE_EC && ($details['ec']['curve_name'] ?? '') === 'prime256v1') {
            return new self($keyPrefix, 'ES256', $key);
        }
        throw new RanteLoginException('invalid_configuration', 'The signing key must be an RSA or EC P-256 private key.');
    }

    /** @internal */
    public function privateKey(): \OpenSSLAsymmetricKey
    {
        return $this->privateKey;
    }
}
