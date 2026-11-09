<?php

declare(strict_types=1);

namespace Rante\Login;

/** A finished sign-in: the validated ID token and the token response. */
final class SignInResult
{
    public function __construct(
        public readonly ValidatedIdToken $idToken,
        public readonly TokenSet $tokens,
    ) {
    }

    public function subject(): string
    {
        return $this->idToken->subject;
    }

    /** @return array<string, mixed> */
    public function claims(): array
    {
        return $this->idToken->claims;
    }

    /** The access token for the userinfo endpoint (15 minutes). */
    public function accessToken(): string
    {
        return $this->tokens->accessToken;
    }
}
