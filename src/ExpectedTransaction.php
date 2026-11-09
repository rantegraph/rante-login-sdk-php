<?php

declare(strict_types=1);

namespace Rante\Login;

/** What a sign-in must match at the redirect URI: its state, nonce and PKCE code verifier. */
final class ExpectedTransaction
{
    public function __construct(
        public readonly string $state,
        public readonly string $nonce,
        public readonly string $codeVerifier,
    ) {
    }

    /** @return array{state: string, nonce: string, codeVerifier: string} for a session */
    public function toArray(): array
    {
        return ['state' => $this->state, 'nonce' => $this->nonce, 'codeVerifier' => $this->codeVerifier];
    }

    /** @param mixed $values what toArray() returned, or anything else (null when it doesn't fit) */
    public static function fromArray(mixed $values): ?self
    {
        if (!is_array($values)) {
            return null;
        }
        $state = $values['state'] ?? null;
        $nonce = $values['nonce'] ?? null;
        $verifier = $values['codeVerifier'] ?? null;
        return is_string($state) && $state !== '' && is_string($nonce) && $nonce !== '' && is_string($verifier) && $verifier !== ''
            ? new self($state, $nonce, $verifier)
            : null;
    }
}
