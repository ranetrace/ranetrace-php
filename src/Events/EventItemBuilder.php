<?php

declare(strict_types=1);

namespace Ranetrace\Php\Events;

use Ranetrace\Php\Support\DataSanitizer;
use Ranetrace\Php\Support\Scrubber;

/**
 * Shapes one tracked event into the seven-key event item the Ranetrace API
 * accepts.
 *
 * Shared with `ranetrace/ranetrace-laravel`. The API does strict field-set
 * matching, so an added or dropped key rejects the whole batch; the key set is
 * exactly these seven and the tests assert it rather than only the values.
 *
 * The fingerprints arrive already hashed, by {@see \Ranetrace\Php\Support\FingerprintGenerator}
 * in both SDKs. They are not computed here because the builder is handed a
 * finished observation of the request, not the request itself.
 */
final class EventItemBuilder
{
    public function __construct(private readonly Scrubber $scrubber) {}

    /**
     * @param  array<array-key, mixed>  $properties  Free-form; sanitized and secret-scrubbed here.
     * @param  array{id: mixed}|null  $user  Only the id travels; events carry no email.
     * @param  string  $timestamp  ISO 8601 capture time, from the host's clock.
     * @param  string|null  $url  The URL of the request the event happened in, unscrubbed. Null for a console process.
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitivePathValues  Path segment values to redact from $url and from any URL hiding in $properties: a fixed list, or a per-URL resolver for a host with a router. Null means query-only scrubbing.
     * @return array{
     *     event_name: string,
     *     properties: mixed,
     *     user: array{id: mixed}|null,
     *     timestamp: string,
     *     url: string|null,
     *     user_agent_hash: string,
     *     session_id_hash: string,
     * }
     */
    public function build(
        string $name,
        array $properties,
        ?array $user,
        string $timestamp,
        ?string $url,
        string $userAgentHash,
        string $sessionIdHash,
        array|callable|null $sensitivePathValues = null,
    ): array {
        return [
            'event_name' => $name,
            // The host's declared path secrets are passed through, so a URL
            // property loses its `{token}` segment the same way the event's own
            // `url` field does.
            'properties' => $this->scrubber->scrubDeep(
                DataSanitizer::sanitizeForSerialization($properties),
                $sensitivePathValues,
            ),
            'user' => $user,
            'timestamp' => $timestamp,
            'url' => $url === null ? null : $this->scrubber->scrubUrlPath(
                $this->scrubber->scrubUrl($url),
                $sensitivePathValues,
            ),
            'user_agent_hash' => $userAgentHash,
            'session_id_hash' => $sessionIdHash,
        ];
    }
}
