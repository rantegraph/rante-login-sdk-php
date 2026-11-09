<?php

declare(strict_types=1);

namespace Rante\Login\Tests;

/**
 * Key pairs for the tests. PHP for Windows can only generate and export keys with an openssl.cnf; its zip carries one
 * in extras/ssl, which is used when OPENSSL_CONF isn't set.
 */
final class Keys
{
    public static function rsa(int $bits = 2048): \OpenSSLAsymmetricKey
    {
        return self::generate(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits]);
    }

    public static function ec(string $curve = 'prime256v1'): \OpenSSLAsymmetricKey
    {
        return self::generate(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
    }

    public static function privatePem(\OpenSSLAsymmetricKey $key): string
    {
        if (!openssl_pkey_export($key, $pem, null, self::config())) {
            throw new \RuntimeException('Key export failed: ' . openssl_error_string());
        }
        return $pem;
    }

    public static function publicPem(\OpenSSLAsymmetricKey $key): string
    {
        return openssl_pkey_get_details($key)['key'];
    }

    /** @param array<string, mixed> $options */
    private static function generate(array $options): \OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new($options + self::config());
        if ($key === false) {
            throw new \RuntimeException('Key generation failed: ' . openssl_error_string());
        }
        return $key;
    }

    /** @return array<string, string> */
    private static function config(): array
    {
        $bundled = dirname(PHP_BINARY) . '/extras/ssl/openssl.cnf';
        return getenv('OPENSSL_CONF') === false && PHP_OS_FAMILY === 'Windows' && is_file($bundled) ? ['config' => $bundled] : [];
    }
}
