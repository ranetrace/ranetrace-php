<?php

declare(strict_types=1);

namespace Ranetrace\Php\JavaScript;

use DateTimeImmutable;
use Ranetrace\Php\Buffer\BufferInterface;
use Ranetrace\Php\Config;
use Ranetrace\Php\Support\DataSanitizer;
use Ranetrace\Php\Support\FingerprintGenerator;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\PayloadSizer;
use Ranetrace\Php\Support\SecretScrubber;
use Throwable;

/**
 * The endpoint the browser capture script posts to: validates what the browser
 * sent, replaces the fields a browser must never be trusted to state, and
 * buffers the result.
 *
 * Ported from `ranetrace/ranetrace-laravel`'s `JavaScriptErrorController`.
 * Two things that were middleware there are not middleware here, because this
 * SDK mounts nothing:
 *
 * 1. CSRF. The Laravel relay sat behind the `web` group, so a forged
 *    cross-origin POST was stopped by the CSRF token. There is no session and no
 *    token here, so the equivalent protection is a same-origin check: when the
 *    request carries an `Origin` (or failing that a `Referer`), its host must
 *    match the request's own `Host` or appear in
 *    `javascript_errors.allowed_origins`. That is why the capture script sends
 *    no `X-CSRF-TOKEN`. A request with neither header is allowed: those are
 *    same-origin navigations and server-to-server calls, and rejecting them
 *    would drop legitimate reports.
 * 2. Rate limiting. The Laravel relay had `throttle:60,1`. This SDK has no
 *    shared store to count against and will not invent one, so THE HOST MUST
 *    RATE LIMIT THE MOUNTED ENDPOINT. It is a public, unauthenticated POST:
 *    without a limit in front of it, a single browser tab in a crash loop can
 *    fill the buffer.
 *
 * Nothing here throws. The browser cannot act on an exception and a 500 loop is
 * worse than a dropped error report, so the whole body is caught.
 */
final class Relay
{
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

    /**
     * The buffer type JavaScript errors are spooled under.
     */
    private const string BUFFER_TYPE = 'javascript_errors';

    /**
     * The only `browser_info` keys that reach the wire, in wire order. The
     * object is rebuilt from this list rather than filtered, so an unknown key
     * from a tampered payload is dropped and a missing one is null: the field
     * set is always exactly these seven.
     *
     * @var array<int, string>
     */
    private const array BROWSER_INFO_KEYS = [
        'screen_width',
        'screen_height',
        'viewport_width',
        'viewport_height',
        'device_memory',
        'hardware_concurrency',
        'connection_type',
    ];

    /**
     * Path segment values to redact from the reported URL. See
     * {@see setSensitivePathValues()}.
     *
     * @var array<int, string>|null
     */
    private ?array $sensitivePathValues = null;

    public function __construct(
        private readonly Config $config,
        private readonly BufferInterface $buffer,
        private readonly SecretScrubber $scrubber,
        private readonly FingerprintGenerator $fingerprints,
        private readonly InternalLogger $log,
    ) {}

    /**
     * Decide what to do with one posted error report.
     *
     * The order of the steps is part of the contract: gates, then the
     * same-origin check, then the Referer fallback for a blank `url` (BEFORE
     * validation, so the validator stays the single source of truth that `url`
     * is present), then validation, then the ignore and sample filters, then
     * the buffered item.
     *
     * @param  array<string, mixed>  $server  Superglobal-shaped request context. `RANETRACE_SESSION_ID` is read as the caller's per-visit id and is hashed, never stored raw.
     * @param  array<string, mixed>  $payload  The decoded JSON body, entirely untrusted.
     */
    public function handleRequest(array $server, array $payload): RelayResponse
    {
        try {
            return $this->process($server, $payload);
        } catch (Throwable $failure) {
            $this->log->error('Failed to process JavaScript error', [
                'exception' => $failure->getMessage(),
            ]);

            return new RelayResponse(500, [
                'success' => false,
                'message' => 'Failed to process error',
            ]);
        }
    }

    /**
     * Superglobal adapter for hosts without a request abstraction: reads the
     * JSON body and `$_SERVER`, then writes the status, the content type and the
     * JSON body out. Headers are skipped when the host already sent some, so
     * this cannot emit a warning into a half-rendered response.
     */
    public function handle(): void
    {
        $raw = @file_get_contents('php://input');
        $decoded = is_string($raw) && $raw !== '' ? json_decode($raw, true) : null;

        $response = $this->handleRequest($_SERVER, is_array($decoded) ? $decoded : []);

        if (! headers_sent()) {
            http_response_code($response->status);
            header('Content-Type: application/json');
        }

        echo $response->toJson();
    }

    /**
     * Declare which URL path segment values hold secrets, so they are redacted
     * from the reported URL. The Laravel relay resolved these from the router;
     * this SDK has no router, so a host that knows (a framework adapter) tells
     * us. Null means query-only URL scrubbing.
     *
     * @param  array<int, string>|null  $values
     */
    public function setSensitivePathValues(?array $values): void
    {
        $this->sensitivePathValues = $values;
    }

    /**
     * @param  array<string, mixed>  $server
     * @param  array<string, mixed>  $payload
     */
    private function process(array $server, array $payload): RelayResponse
    {
        if (! $this->config->enabled()) {
            return new RelayResponse(403, [
                'success' => false,
                'message' => 'Ranetrace is not enabled',
            ]);
        }

        if (! $this->config->enabled('javascript_errors')) {
            return new RelayResponse(403, [
                'success' => false,
                'message' => 'JavaScript error tracking is not enabled',
            ]);
        }

        if (! $this->originAllowed($server)) {
            return new RelayResponse(403, [
                'success' => false,
                'message' => 'Origin not allowed',
            ]);
        }

        if ($this->isBlank($payload['url'] ?? null)) {
            $payload['url'] = $this->headerString($server, 'HTTP_REFERER');
        }

        $errors = $this->validate($payload);

        if ($errors !== []) {
            return new RelayResponse(422, [
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $errors,
            ]);
        }

        $message = (string) $payload['message'];

        if ($this->isIgnored($message)) {
            return new RelayResponse(200, [
                'success' => true,
                'message' => 'Error ignored based on pattern',
            ]);
        }

        if ($this->isSampledOut()) {
            return new RelayResponse(200, [
                'success' => true,
                'message' => 'Error sampled out',
            ]);
        }

        if (! $this->buffer->addItem(self::BUFFER_TYPE, $this->buildItem($server, $payload, $message))) {
            // A rejected write is a transient drop (lock contention, unwritable
            // spool), already recorded by the buffer's own diagnostics. The
            // browser can do nothing about it and retrying would only amplify
            // whatever is wrong, so the report is acknowledged and dropped.
            $this->log->warning('JavaScript error could not be buffered', ['message' => $message]);
        }

        return new RelayResponse(200, [
            'success' => true,
            'message' => 'Error received',
        ]);
    }

    /**
     * The 15-key buffered item. Every key is always present and the set is
     * exact: the API does strict field-set matching, so one extra or missing key
     * rejects the whole batch.
     *
     * `user_agent`, `environment`, `user_id` and `session_id` are server-added
     * and never read from the payload, because a browser can claim anything.
     *
     * @param  array<string, mixed>  $server
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    private function buildItem(array $server, array $payload, string $message): array
    {
        $stack = $payload['stack'] ?? null;
        $url = (string) $payload['url'];

        return [
            'message' => $this->scrubber->scrubString($message),
            'stack' => is_string($stack) ? $this->scrubber->scrubString($stack) : null,
            'type' => isset($payload['type']) && is_string($payload['type']) ? $payload['type'] : 'Error',
            'filename' => isset($payload['filename']) && is_string($payload['filename']) ? $payload['filename'] : null,
            'line' => $this->intOrNull($payload['line'] ?? null),
            'column' => $this->intOrNull($payload['column'] ?? null),
            'user_agent' => $this->headerString($server, 'HTTP_USER_AGENT'),
            // The reported URL is the page the error happened on, not this POST
            // endpoint, so it gets scrubbed on its own terms: query first, then
            // whichever path segments the host declared secret-bearing.
            'url' => $this->scrubber->scrubUrlPath($this->scrubber->scrubUrl($url), $this->sensitivePathValues),
            'timestamp' => $this->timestamp($payload),
            'environment' => (string) $this->config->get('environment', 'production'),
            'user_id' => $this->resolveUserId(),
            // Hashed, never raw, so a leaked payload cannot be replayed as a
            // session while errors can still be grouped per visit.
            'session_id' => $this->sessionId($server),
            'breadcrumbs' => $this->normalizeBreadcrumbs($payload['breadcrumbs'] ?? []),
            'context' => PayloadSizer::capBytes(
                $this->scrubbedArray($payload['context'] ?? []),
                self::MAX_CONTEXT_BYTES,
                'Context exceeded 50KB limit and was removed',
            ),
            'browser_info' => $this->browserInfo($payload['browser_info'] ?? []),
        ];
    }

    /**
     * Whether the request's origin is trusted. See the class docblock: this is
     * the replacement for the CSRF token the Laravel relay relied on.
     *
     * @param  array<string, mixed>  $server
     */
    private function originAllowed(array $server): bool
    {
        $origin = $this->headerString($server, 'HTTP_ORIGIN')
            ?? $this->headerString($server, 'HTTP_REFERER');

        if ($origin === null) {
            return true;
        }

        $normalized = $this->normalizeOrigin($origin);

        if ($normalized === null) {
            return false;
        }

        $host = $this->headerString($server, 'HTTP_HOST') ?? $this->headerString($server, 'SERVER_NAME');

        if ($host !== null && $this->normalizeAuthority($host) === $this->authorityOf($normalized)) {
            return true;
        }

        $allowed = $this->config->get('javascript_errors.allowed_origins', []);

        if (! is_array($allowed)) {
            return false;
        }

        foreach ($allowed as $candidate) {
            if (! is_string($candidate) || $candidate === '') {
                continue;
            }

            $candidateOrigin = $this->normalizeOrigin($candidate);

            // An allowlist entry may be a full origin (`https://app.test`) or a
            // bare authority (`app.test:8443`); both spellings are accepted
            // because both are what people actually write in configuration.
            if ($candidateOrigin !== null && $candidateOrigin === $normalized) {
                return true;
            }

            if ($candidateOrigin === null && $this->normalizeAuthority($candidate) === $this->authorityOf($normalized)) {
                return true;
            }
        }

        return false;
    }

    /**
     * `scheme://host[:port]` in lowercase with the scheme's default port
     * dropped, or null when the value carries no scheme and host.
     */
    private function normalizeOrigin(string $value): ?string
    {
        $parts = parse_url($value);

        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $scheme = mb_strtolower((string) $parts['scheme']);
        $origin = $scheme.'://'.mb_strtolower((string) $parts['host']);
        $port = $parts['port'] ?? null;

        if ($port !== null && ! $this->isDefaultPort($scheme, (int) $port)) {
            $origin .= ':'.$port;
        }

        return $origin;
    }

    /**
     * The `host[:port]` part of a normalized origin, for comparison against a
     * `Host` header, which carries no scheme.
     */
    private function authorityOf(string $origin): string
    {
        $position = mb_strpos($origin, '://');

        return $position === false ? $origin : mb_substr($origin, $position + 3);
    }

    /**
     * A `Host`-header-shaped value in lowercase with a default port dropped, so
     * `Example.test:443` and `example.test` compare equal.
     */
    private function normalizeAuthority(string $host): string
    {
        $host = mb_strtolower(mb_rtrim(mb_trim($host), '/'));
        $position = mb_strrpos($host, ':');

        if ($position === false) {
            return $host;
        }

        $port = mb_substr($host, $position + 1);

        if (! is_numeric($port)) {
            return $host;
        }

        $name = mb_substr($host, 0, $position);

        return $this->isDefaultPort('http', (int) $port) || $this->isDefaultPort('https', (int) $port)
            ? $name
            : $host;
    }

    private function isDefaultPort(string $scheme, int $port): bool
    {
        return ($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443);
    }

    /**
     * The Laravel validator's rule set from spec section 5.3, in plain PHP.
     * Message wording follows Laravel's defaults so a host migrating from the
     * Laravel SDK sees the same bodies; the key set is what the contract fixes.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, array<int, string>>
     */
    private function validate(array $payload): array
    {
        $errors = [];

        $this->assertString($errors, $payload, 'message', true, 2000);
        $this->assertString($errors, $payload, 'stack', false, 10000);
        $this->assertString($errors, $payload, 'type', false, 100);
        $this->assertString($errors, $payload, 'filename', false, 500);
        $this->assertInteger($errors, $payload, 'line');
        $this->assertInteger($errors, $payload, 'column');
        $this->assertString($errors, $payload, 'url', true, 2000);
        $this->assertString($errors, $payload, 'timestamp', false, 64);
        $this->assertArrayValue($errors, $payload, 'breadcrumbs');
        $this->assertArrayValue($errors, $payload, 'context');
        $this->assertArrayValue($errors, $payload, 'browser_info');

        $breadcrumbs = $payload['breadcrumbs'] ?? null;

        if (is_array($breadcrumbs)) {
            foreach ($breadcrumbs as $index => $breadcrumb) {
                $crumb = is_array($breadcrumb) ? $breadcrumb : [];

                $this->assertString($errors, $crumb, "breadcrumbs.{$index}.timestamp", true, 64, 'timestamp');
                $this->assertString($errors, $crumb, "breadcrumbs.{$index}.category", true, 100, 'category');
                $this->assertString($errors, $crumb, "breadcrumbs.{$index}.message", true, 500, 'message');
                $this->assertArrayValue($errors, $crumb, "breadcrumbs.{$index}.data", 'data');
            }
        }

        $browserInfo = $payload['browser_info'] ?? null;

        if (is_array($browserInfo)) {
            foreach (self::BROWSER_INFO_KEYS as $key) {
                if ($key === 'connection_type') {
                    $this->assertString($errors, $browserInfo, 'browser_info.connection_type', false, 50, 'connection_type');

                    continue;
                }

                $this->assertNumeric($errors, $browserInfo, 'browser_info.'.$key, $key);
            }
        }

        return $errors;
    }

    /**
     * @param  array<string, array<int, string>>  $errors
     * @param  array<array-key, mixed>  $container
     */
    private function assertString(array &$errors, array $container, string $key, bool $required, ?int $max, ?string $lookup = null): void
    {
        $lookup ??= $key;
        $value = $container[$lookup] ?? null;

        if ($required && $this->isBlank($value)) {
            $errors[$key][] = "The {$key} field is required.";

            return;
        }

        if ($value === null) {
            return;
        }

        if (! is_string($value)) {
            $errors[$key][] = "The {$key} field must be a string.";

            return;
        }

        if ($max !== null && mb_strlen($value) > $max) {
            $errors[$key][] = "The {$key} field must not be greater than {$max} characters.";
        }
    }

    /**
     * @param  array<string, array<int, string>>  $errors
     * @param  array<array-key, mixed>  $container
     */
    private function assertInteger(array &$errors, array $container, string $key, ?string $lookup = null): void
    {
        $value = $container[$lookup ?? $key] ?? null;

        if ($value === null) {
            return;
        }

        // Booleans are excluded explicitly: filter_var() happily reads true as 1.
        if (is_bool($value) || filter_var($value, FILTER_VALIDATE_INT) === false) {
            $errors[$key][] = "The {$key} field must be an integer.";
        }
    }

    /**
     * @param  array<string, array<int, string>>  $errors
     * @param  array<array-key, mixed>  $container
     */
    private function assertNumeric(array &$errors, array $container, string $key, ?string $lookup = null): void
    {
        $value = $container[$lookup ?? $key] ?? null;

        if ($value === null) {
            return;
        }

        if (! is_numeric($value)) {
            $errors[$key][] = "The {$key} field must be a number.";
        }
    }

    /**
     * @param  array<string, array<int, string>>  $errors
     * @param  array<array-key, mixed>  $container
     */
    private function assertArrayValue(array &$errors, array $container, string $key, ?string $lookup = null): void
    {
        $value = $container[$lookup ?? $key] ?? null;

        if ($value === null) {
            return;
        }

        if (! is_array($value)) {
            $errors[$key][] = "The {$key} field must be an array.";
        }
    }

    /**
     * Laravel's `blank()` for the values a JSON body can hold: null, a string
     * that is only whitespace, and an empty array.
     */
    private function isBlank(mixed $value): bool
    {
        if ($value === null) {
            return true;
        }

        if (is_string($value)) {
            return mb_trim($value) === '';
        }

        return is_array($value) && $value === [];
    }

    private function isIgnored(string $message): bool
    {
        $patterns = $this->config->get('javascript_errors.ignored_errors', Config::DEFAULT_IGNORED_JAVASCRIPT_ERRORS);

        if (! is_array($patterns)) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if (! is_string($pattern) || $pattern === '') {
                continue;
            }

            if (mb_stripos($message, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Server-side sampling, on top of the script's own client-side gate: a
     * stale cached script cannot outvote a lowered sample rate.
     */
    private function isSampledOut(): bool
    {
        $rate = $this->config->get('javascript_errors.sample_rate', 1.0);
        $rate = is_numeric($rate) ? (float) $rate : 1.0;

        return $rate < 1.0 && mt_rand() / mt_getrandmax() > $rate;
    }

    /**
     * Keep the LAST N breadcrumbs (the ones nearest the error are the
     * diagnostic ones) and rebuild each as exactly the four wire keys, so a
     * browser cannot smuggle a fifth.
     *
     * @param  mixed  $breadcrumbs  Validated to be an array or absent by this point.
     * @return array<int, array{timestamp: mixed, category: mixed, message: mixed, data: array<array-key, mixed>}>
     */
    private function normalizeBreadcrumbs(mixed $breadcrumbs): array
    {
        if (! is_array($breadcrumbs)) {
            return [];
        }

        $max = $this->config->get('javascript_errors.max_breadcrumbs', 20);
        $max = is_numeric($max) ? (int) $max : 20;

        $kept = $max > 0 ? array_slice(array_values($breadcrumbs), -$max) : [];

        return array_map(function (mixed $breadcrumb): array {
            $breadcrumb = is_array($breadcrumb) ? $breadcrumb : [];

            return [
                'timestamp' => $breadcrumb['timestamp'] ?? null,
                'category' => $breadcrumb['category'] ?? null,
                'message' => $breadcrumb['message'] ?? null,
                'data' => PayloadSizer::capBytes(
                    $this->scrubbedArray($breadcrumb['data'] ?? []),
                    self::MAX_BREADCRUMB_DATA_BYTES,
                    'Breadcrumb data exceeded 5KB limit and was removed',
                ),
            ];
        }, $kept);
    }

    /**
     * Exactly seven keys, always, in wire order. Unknown keys are dropped by
     * construction and missing ones are null.
     *
     * @return array<string, mixed>
     */
    private function browserInfo(mixed $browserInfo): array
    {
        $source = is_array($browserInfo) ? $browserInfo : [];
        $info = [];

        foreach (self::BROWSER_INFO_KEYS as $key) {
            $info[$key] = $source[$key] ?? null;
        }

        return $info;
    }

    /**
     * Sanitize for serialization, then redact secret-keyed values and secrets
     * hiding in URL-shaped values.
     *
     * @return array<array-key, mixed>
     */
    private function scrubbedArray(mixed $value): array
    {
        $scrubbed = $this->scrubber->scrubDeep(DataSanitizer::sanitizeForSerialization($value));

        return is_array($scrubbed) ? $scrubbed : [];
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function timestamp(array $payload): string
    {
        $timestamp = $payload['timestamp'] ?? null;

        if (is_string($timestamp) && mb_trim($timestamp) !== '') {
            return $timestamp;
        }

        return (new DateTimeImmutable)->format('c');
    }

    private function resolveUserId(): int|string|null
    {
        $resolver = $this->config->get('user_resolver');

        if (! is_callable($resolver)) {
            return null;
        }

        $resolved = $resolver();

        if (! is_array($resolved) || ! isset($resolved['id'])) {
            return null;
        }

        $id = $resolved['id'];

        return is_int($id) || is_string($id) ? $id : null;
    }

    /**
     * The caller's per-visit id, hashed. Null when the host supplied none: a
     * hash of an empty string would look like a real session that every
     * anonymous visitor shares.
     *
     * @param  array<string, mixed>  $server
     */
    private function sessionId(array $server): ?string
    {
        $raw = $this->headerString($server, 'RANETRACE_SESSION_ID');

        return $raw === null ? null : $this->fingerprints->hash($raw);
    }

    /**
     * One request-context value as a non-empty string, or null.
     *
     * @param  array<string, mixed>  $server
     */
    private function headerString(array $server, string $key): ?string
    {
        $value = $server[$key] ?? null;

        if (! is_scalar($value)) {
            return null;
        }

        $value = (string) $value;

        return $value === '' ? null : $value;
    }

    private function intOrNull(mixed $value): ?int
    {
        if ($value === null || is_bool($value)) {
            return null;
        }

        return is_numeric($value) ? (int) $value : null;
    }
}
