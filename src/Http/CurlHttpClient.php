<?php

declare(strict_types=1);

namespace Rante\Login\Http;

/** The default HttpClient, on PHP's curl extension. */
final class CurlHttpClient implements HttpClient
{
    public function __construct(private readonly int $timeoutSeconds = 10)
    {
    }

    public function send(string $method, string $url, array $headers, ?array $form = null): HttpResponse
    {
        $curl = curl_init($url);
        if ($curl === false) {
            throw new \RuntimeException('curl could not start.');
        }
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        $options = [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_CONNECTTIMEOUT => $this->timeoutSeconds,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
        ];
        // PHP for Windows has no CA bundle unless php.ini names one (curl.cainfo): use the Windows certificate store.
        if (PHP_OS_FAMILY === 'Windows' && (string) ini_get('curl.cainfo') === '' && defined('CURLSSLOPT_NATIVE_CA')) {
            $options[CURLOPT_SSL_OPTIONS] = CURLSSLOPT_NATIVE_CA;
        }
        if ($form !== null) {
            $options[CURLOPT_POSTFIELDS] = http_build_query($form, '', '&', PHP_QUERY_RFC1738);
            $lines[] = 'Content-Type: application/x-www-form-urlencoded';
            $options[CURLOPT_HTTPHEADER] = $lines;
        }
        curl_setopt_array($curl, $options);
        $body = curl_exec($curl);
        if ($body === false) {
            $error = curl_error($curl);
            throw new \RuntimeException('Rante Login could not be reached: ' . $error);
        }
        return new HttpResponse((int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE), (string) $body);
    }
}
