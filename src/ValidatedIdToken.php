<?php

declare(strict_types=1);

namespace Rante\Login;

/** A validated ID token. */
final class ValidatedIdToken
{
    /**
     * @param string $subject the person's ID on your website: pairwise, so the same for your organization's apps and
     *                        different for other organizations
     * @param array<string, mixed> $claims the token's claims, by their JWT names
     */
    public function __construct(
        public readonly string $subject,
        public readonly array $claims,
    ) {
    }
}
