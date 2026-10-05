<?php

declare(strict_types=1);

namespace Ranetrace\Php\JavaScript;

use DateTimeImmutable;
use Ranetrace\Php\Config;
use Ranetrace\Php\Support\BrowserIdentity;
use Ranetrace\Php\Support\DataSanitizer;
use Ranetrace\Php\Support\PayloadSizer;
use Ranetrace\Php\Support\Scrubber;
use Ranetrace\Php\Support\UserId;
use Ranetrace\Php\Support\Utf8;

/**
 * Shapes one browser error report into the fifteen-key JavaScript error item
 * the Ranetrace API accepts.
 *
 * Shared with `ranetrace/ranetrace-laravel`. Every key is always present and the
 * set is exact: the API does strict field-set matching, so one extra or missing
 * key rejects the whole batch.
 *
 * The payload is entirely untrusted, so the item is REBUILT from it rather than
 * filtered: an unknown key from a tampered payload is dropped by construction
 * and a missing one is null. `user_agent`, `environment`, `user_id` and
 * `session_id` never come from the payload at all, because a browser can claim
 * anything; the host observes them and passes them in. For the same reason the
 * browser's `name` and `version` in `browser_info` are derived from that
 * host-observed user agent, never read from the payload.
 *
 * Every string, array keys included, passes through {@see Utf8} before it is
 * scrubbed or capped. A JSON body cannot carry an invalid byte, but a payload a
 * host decoded from a form post can, and so can the user agent header.
 */
final class ErrorItemBuilder
{
    /**
     * The `browser_info` keys taken from the browser payload, in wire order.
     * On the wire they are followed by `name` and `version`, which the builder
     * derives from the host-observed user agent, so a payload's own `name` or
     * `version` is dropped with every other unknown key.
     *
     * @var array<int, string>
     */
    public const array BROWSER_INFO_KEYS = [
        'screen_width',
        'screen_height',
        'viewport_width',
        'viewport_height',
        'device_memory',
        'hardware_concurrency',
        'connection_type',
    ];

    /**
     * Maximum serialized context size (JSON-encoded bytes). Oversize context is
     * replaced with a truncation marker rather than truncated mid-structure,
     * because partial JSON is not JSON.
     */
    private const int MAX_CONTEXT_BYTES = 51_200;

    /**
     * Maximum serialized data size per breadcrumb (JSON-encoded bytes).
     */
    private const int MAX_BREADCRUMB_DATA_BYTES = 5_120;

    public function __construct(
        private readonly Config $config,
        private readonly Scrubber $scrubber,
    ) {}

    /**
     * @param  array<string, mixed>  $payload  The validated browser payload.
     * @param  string|null  $userAgent  Observed by the host, never read from the payload.
     * @param  int|string|null  $userId  The authenticated user, as the host knows them. A string the backend would reject for its length is sent as null.
     * @param  string|null  $sessionId  Already hashed. Never the raw session id: a leaked payload must not be replayable as a session.
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitivePathValues  Path segment values to redact from the reported URL and from any URL inside the breadcrumbs or context: a fixed list, or a per-URL resolver for a host with a router.
     * @param  string|null  $timestampFallback  Used when the payload names no timestamp. Null reads this process's clock, which a host with a freezable clock of its own will not want.
     * @return array<string, mixed>
     */
    public function build(
        array $payload,
        ?string $userAgent,
        int|string|null $userId,
        ?string $sessionId,
        array|callable|null $sensitivePathValues = null,
        ?string $timestampFallback = null,
    ): array {
        $stack = $payload['stack'] ?? null;
        $message = isset($payload['message']) && is_scalar($payload['message']) ? (string) $payload['message'] : '';
        $url = isset($payload['url']) && is_scalar($payload['url']) ? (string) $payload['url'] : '';

        return [
            'message' => $this->scrubber->scrubString(Utf8::repair($message)),
            'stack' => is_string($stack) ? $this->scrubber->scrubString(Utf8::repair($stack)) : null,
            'type' => isset($payload['type']) && is_string($payload['type']) ? Utf8::repair($payload['type']) : 'Error',
            'filename' => isset($payload['filename']) && is_string($payload['filename']) ? Utf8::repair($payload['filename']) : null,
            'line' => $this->intOrNull($payload['line'] ?? null),
            'column' => $this->intOrNull($payload['column'] ?? null),
            'user_agent' => Utf8::repairNullable($userAgent),
            // The reported URL is the page the error happened on, not the
            // endpoint it was posted to, so it gets scrubbed on its own terms:
            // query first, then whichever path segments the host declared
            // secret-bearing for THAT url.
            'url' => $this->scrubber->scrubUrlPath($this->scrubber->scrubUrl(Utf8::repair($url)), $sensitivePathValues),
            'timestamp' => $this->timestamp($payload, $timestampFallback),
            'environment' => Utf8::repair((string) $this->config->get('environment', 'production')),
            'user_id' => UserId::accepted($userId),
            'session_id' => Utf8::repairNullable($sessionId),
            'breadcrumbs' => $this->breadcrumbs($payload['breadcrumbs'] ?? [], $sensitivePathValues),
            'context' => PayloadSizer::capBytes(
                $this->scrubbedArray($payload['context'] ?? [], $sensitivePathValues),
                self::MAX_CONTEXT_BYTES,
                'Context exceeded 50KB limit and was removed',
            ),
            'browser_info' => $this->browserInfo($payload['browser_info'] ?? [], $userAgent),
        ];
    }

    /**
     * Keep the LAST N breadcrumbs (the ones nearest the error are the
     * diagnostic ones) and rebuild each as exactly the four wire keys, so a
     * browser cannot smuggle a fifth.
     *
     * @param  mixed  $breadcrumbs  Validated to be an array or absent by this point.
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitivePathValues
     * @return array<int, array{timestamp: mixed, category: mixed, message: mixed, data: array<array-key, mixed>}>
     */
    private function breadcrumbs(mixed $breadcrumbs, array|callable|null $sensitivePathValues): array
    {
        if (! is_array($breadcrumbs)) {
            return [];
        }

        $max = $this->config->get('javascript_errors.max_breadcrumbs', 20);
        $max = is_numeric($max) ? (int) $max : 20;

        $kept = $max > 0 ? array_slice(array_values($breadcrumbs), -$max) : [];

        return array_map(function (mixed $breadcrumb) use ($sensitivePathValues): array {
            $breadcrumb = is_array($breadcrumb) ? $breadcrumb : [];

            return [
                'timestamp' => Utf8::repairDeep($breadcrumb['timestamp'] ?? null),
                'category' => Utf8::repairDeep($breadcrumb['category'] ?? null),
                'message' => Utf8::repairDeep($breadcrumb['message'] ?? null),
                'data' => PayloadSizer::capBytes(
                    $this->scrubbedArray($breadcrumb['data'] ?? [], $sensitivePathValues),
                    self::MAX_BREADCRUMB_DATA_BYTES,
                    'Breadcrumb data exceeded 5KB limit and was removed',
                ),
            ];
        }, $kept);
    }

    /**
     * Exactly nine keys, always, in wire order: the seven the browser reports,
     * then the `name` and `version` its user agent names. Unknown keys are
     * dropped by construction and missing ones are null.
     *
     * @return array<string, mixed>
     */
    private function browserInfo(mixed $browserInfo, ?string $userAgent): array
    {
        $source = is_array($browserInfo) ? $browserInfo : [];
        $info = [];

        foreach (self::BROWSER_INFO_KEYS as $key) {
            $info[$key] = Utf8::repairDeep($source[$key] ?? null);
        }

        $browser = BrowserIdentity::fromUserAgent($userAgent);

        $info['name'] = $browser->name;
        $info['version'] = $browser->version;

        return $info;
    }

    /**
     * Sanitize for serialization, then redact secret-keyed values and secrets
     * hiding in URL-shaped values.
     *
     * The host's declared path secrets are passed through, so a reset link the
     * tracker recorded as a navigation breadcrumb loses its `{token}` segment
     * the same way the top-level `url` field does. Otherwise the same payload
     * would redact the secret in one field and ship it in another.
     *
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitivePathValues
     * @return array<array-key, mixed>
     */
    private function scrubbedArray(mixed $value, array|callable|null $sensitivePathValues): array
    {
        $scrubbed = $this->scrubber->scrubDeep(
            Utf8::repairDeep(DataSanitizer::sanitizeForSerialization($value)),
            $sensitivePathValues,
        );

        return is_array($scrubbed) ? $scrubbed : [];
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function timestamp(array $payload, ?string $fallback): string
    {
        $timestamp = $payload['timestamp'] ?? null;
        $timestamp = is_string($timestamp) ? Utf8::repair($timestamp) : null;

        if ($timestamp !== null && mb_trim($timestamp) !== '') {
            return $timestamp;
        }

        return Utf8::repairNullable($fallback) ?? (new DateTimeImmutable)->format('c');
    }

    /**
     * The value as an integer, or null when it is not a number or is one no
     * integer can represent (INF, NAN, past the integer range). Casting such a
     * float warns on PHP 8.5, which a host that turns warnings into exceptions
     * would turn into a lost report.
     */
    private function intOrNull(mixed $value): ?int
    {
        if (! (is_int($value) || is_float($value) || is_string($value)) || ! is_numeric($value)) {
            return null;
        }

        $number = $value + 0;

        if (is_int($number)) {
            return $number;
        }

        if (! is_finite($number) || $number < PHP_INT_MIN || $number >= PHP_INT_MAX) {
            return null;
        }

        return (int) $number;
    }
}
