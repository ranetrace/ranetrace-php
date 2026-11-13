<?php

declare(strict_types=1);

namespace Ranetrace\Php\Events;

use Ranetrace\Php\Support\DataSanitizer;
use Ranetrace\Php\Support\Scrubber;
use Ranetrace\Php\Support\UserId;
use Ranetrace\Php\Support\Utf8;
use Ranetrace\Php\Support\Uuid;

/**
 * Shapes one tracked event into the eight-key event item the Ranetrace API
 * accepts.
 *
 * Shared with `ranetrace/ranetrace-laravel`. The key set is exactly these
 * eight, the ones `contract/items/events.json` declares, and the tests assert
 * the set rather than only the values.
 *
 * The `id` is made here, once, when the event is captured. The API holds it
 * for thirty minutes and ignores an event whose id it has stored, so a batch
 * that is sent again after its answer was lost is not stored twice, while two
 * events alike in every other field are both stored. That only works when the
 * id belongs to the capture and not to an attempt: it is part of the item, so
 * it stays the same through a queue job that runs twice, a put-back into the
 * spool and every later send.
 *
 * The fingerprints arrive already hashed, by {@see \Ranetrace\Php\Support\FingerprintGenerator}
 * in both SDKs. They are not computed here because the builder is handed a
 * finished observation of the request, not the request itself.
 *
 * Every string, property keys included, passes through {@see Utf8} first, so an
 * invalid byte becomes U+FFFD rather than failing the JSON encode of the item.
 */
final class EventItemBuilder
{
    public function __construct(private readonly Scrubber $scrubber) {}

    /**
     * @param  array<array-key, mixed>  $properties  Free-form; sanitized and secret-scrubbed here.
     * @param  array{id: mixed}|null  $user  Only the id travels; events carry no email. An id the backend would reject sends no user.
     * @param  string  $timestamp  ISO 8601 capture time, from the host's clock.
     * @param  string|null  $url  The URL of the request the event happened in, unscrubbed. Null for a console process.
     * @param  string|null  $userAgentHash  Null when the request carried no user agent, and for a console process.
     * @param  string|null  $sessionIdHash  Null for a console process, which has no visitor to tell apart from another.
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitivePathValues  Path segment values to redact from $url and from any URL hiding in $properties: a fixed list, or a per-URL resolver for a host with a router. Null means query-only scrubbing.
     * @return array{
     *     id: string,
     *     event_name: string,
     *     properties: mixed,
     *     user: array{id: int|string}|null,
     *     timestamp: string,
     *     url: string|null,
     *     user_agent_hash: string|null,
     *     session_id_hash: string|null,
     * }
     */
    public function build(
        string $name,
        array $properties,
        ?array $user,
        string $timestamp,
        ?string $url,
        ?string $userAgentHash,
        ?string $sessionIdHash,
        array|callable|null $sensitivePathValues = null,
    ): array {
        $userId = UserId::accepted($user['id'] ?? null);

        return [
            'id' => Uuid::v4(),
            'event_name' => Utf8::repair($name),
            // The host's declared path secrets are passed through, so a URL
            // property loses its `{token}` segment the same way the event's own
            // `url` field does.
            'properties' => $this->scrubber->scrubDeep(
                Utf8::repairDeep(DataSanitizer::sanitizeForSerialization($properties)),
                $sensitivePathValues,
            ),
            'user' => $userId === null ? null : ['id' => $userId],
            'timestamp' => Utf8::repair($timestamp),
            'url' => $url === null ? null : $this->scrubber->scrubUrlPath(
                $this->scrubber->scrubUrl(Utf8::repair($url)),
                $sensitivePathValues,
            ),
            'user_agent_hash' => Utf8::repairNullable($userAgentHash),
            'session_id_hash' => Utf8::repairNullable($sessionIdHash),
        ];
    }
}
