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
 * The fingerprints arrive already hashed. They are per SDK on purpose: each one
 * salts its HMAC with what its own installs have always used, so computing them
 * here would silently re-key every existing install's hashes and break the join
 * between its events and its visits.
 */
final class EventItemBuilder
{
    public function __construct(private readonly Scrubber $scrubber) {}

    /**
     * @param  array<array-key, mixed>  $properties  Free-form; sanitized and secret-scrubbed here.
     * @param  array{id: mixed}|null  $user  Only the id travels; events carry no email.
     * @param  string  $timestamp  ISO 8601 capture time, from the host's clock.
     * @param  string|null  $url  The URL of the request the event happened in, unscrubbed. Null for a console process.
     * @param  array<int, string>|null  $sensitivePathValues  Path segment values to redact from $url and from any URL hiding in $properties. Null means query-only scrubbing.
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
        ?array $sensitivePathValues = null,
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
