<?php

declare(strict_types=1);

namespace Rante\Login;

/** The userinfo endpoint's answer. */
final class UserInfo
{
    /** @param array<string, mixed> $claims */
    public function __construct(
        public readonly string $subject,
        public readonly array $claims,
    ) {
    }
}
