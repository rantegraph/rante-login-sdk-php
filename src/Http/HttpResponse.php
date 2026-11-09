<?php

declare(strict_types=1);

namespace Rante\Login\Http;

final class HttpResponse
{
    public function __construct(
        public readonly int $status,
        public readonly string $body,
    ) {
    }

    /**
     * The body as a JSON object, or null when it isn't one.
     *
     * @return array<string, mixed>|null
     */
    public function json(): ?array
    {
        $value = json_decode($this->body, true);
        if (!is_array($value) || ($value !== [] && array_is_list($value))) {
            return null;
        }
        return $value;
    }
}
