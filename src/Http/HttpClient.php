<?php

declare(strict_types=1);

namespace Rante\Login\Http;

/**
 * The calls the SDK makes to Rante Login. CurlHttpClient is the default; implement this to use a proxy or another
 * HTTP library. Implementations must not follow redirects, and throw \RuntimeException when the server can't be
 * reached.
 */
interface HttpClient
{
    /**
     * @param array<string, string> $headers
     * @param array<string, string>|null $form a URL-encoded form body, for POST
     */
    public function send(string $method, string $url, array $headers, ?array $form = null): HttpResponse;
}
