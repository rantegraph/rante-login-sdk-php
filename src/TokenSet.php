<?php

declare(strict_types=1);

namespace Rante\Login;

/** The token endpoint's answer. */
final class TokenSet
{
    public function __construct(
        public readonly string $accessToken,
        public readonly string $tokenType,
        public readonly ?int $expiresIn,
        public readonly string $idToken,
        public readonly ?string $scope,
    ) {
    }
}
