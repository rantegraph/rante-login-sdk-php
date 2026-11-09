<?php

declare(strict_types=1);

namespace Rante\Login;

/**
 * A sign-in the server starts: send the browser to $url, and keep $state, $nonce and $codeVerifier on the server (in
 * the session) until it comes back to the redirect URI.
 */
final class AuthorizationRequest
{
    public function __construct(
        public readonly string $url,
        public readonly string $state,
        public readonly string $nonce,
        public readonly string $codeVerifier,
    ) {
    }

    /** What the sign-in must match at the redirect URI. */
    public function toExpected(): ExpectedTransaction
    {
        return new ExpectedTransaction($this->state, $this->nonce, $this->codeVerifier);
    }
}
