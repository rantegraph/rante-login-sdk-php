<?php

declare(strict_types=1);

namespace Rante\Login;

/**
 * Every failure the SDK reports. errorCode is stable and safe to show; OAuth errors (access_denied, invalid_grant,
 * invalid_client, ...) keep their own codes. status is the HTTP status when the error came from Rante Login.
 */
final class RanteLoginException extends \RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message = '',
        public readonly ?int $status = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message === '' ? $errorCode : $message, 0, $previous);
    }
}
