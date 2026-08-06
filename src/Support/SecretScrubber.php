<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use Ranetrace\Php\Config;

/**
 * Redacts values stored under sensitive keys before telemetry leaves the host.
 *
 * Applied to log context/extra, event properties, JS breadcrumbs and exception
 * traces so that a secret a developer accidentally logged never reaches the
 * Ranetrace backend. Matching is a case-insensitive substring test on the key
 * name. The built-in fragment list is always applied and can be extended (never
 * shrunk) via the `scrubbing.extra_keys` config value.
 *
 * Ported from `ranetrace/ranetrace-laravel` (`src/Utilities/SecretScrubber.php`).
 * The redaction semantics are part of the privacy promise the two SDKs share:
 * they must not drift. Only the config lookup changed, from a Laravel facade to
 * an injected {@see Config}.
 */
final class SecretScrubber
{
    public const string REDACTION = '[REDACTED]';

    /**
     * Built-in sensitive key fragments (case-insensitive substring match).
     *
     * @var array<int, string>
     */
    private const array DEFAULT_KEYS = [
        'password',
        'passwd',
        'secret',
        'token',
        'api_key',
        'apikey',
        'api-key',
        'authorization',
        'credential',
        'private_key',
        'access_key',
        'signature',
    ];

    /**
     * Extra sensitive fragments applied to ROUTE-PARAMETER NAMES only.
     *
     * `hash` belongs here rather than in {@see DEFAULT_KEYS}: a stock
     * `email/verify/{id}/{hash}` route puts a verification hash in the path,
     * but telemetry elsewhere carries deliberately-hashed, non-secret keys such
     * as `user_agent_hash` and `session_id_hash` which must survive scrubbing.
     *
     * @var array<int, string>
     */
    private const array ROUTE_PARAMETER_KEYS = [
        'hash',
    ];

    /**
     * Built-in fragments merged with the user-configured extensions, resolved
     * once per instance.
     *
     * @var array<int, string>|null
     */
    private ?array $fragments = null;

    public function __construct(private readonly Config $config) {}

    /**
     * Recursively redact array values whose key matches a sensitive fragment.
     *
     * Non-array input is returned untouched, so this composes directly with the
     * `mixed` return of {@see DataSanitizer::sanitizeForSerialization()}.
     */
    public function scrub(mixed $data): mixed
    {
        if (! is_array($data)) {
            return $data;
        }

        return $this->scrubArray($data, $this->sensitiveFragments());
    }

    /**
     * Like {@see scrub()} (key-based redaction), but ALSO scrubs sensitive
     * query-string params inside URL-shaped string VALUES, catching a secret
     * in an innocuously-keyed URL (e.g. a breadcrumb `data.endpoint` of
     * `https://api/x?token=…`) that key-based scrubbing alone would miss.
     *
     * Intended for free-form, untrusted breadcrumb/context data. Composes with
     * the `mixed` return of {@see DataSanitizer::sanitizeForSerialization()},
     * which has already bounded the recursion depth.
     */
    public function scrubDeep(mixed $data): mixed
    {
        return $this->scrubUrlValues($this->scrub($data));
    }

    /**
     * Redact sensitive query-string parameters within a URL, preserving the
     * scheme, host, path and fragment. Non-sensitive params keep their exact
     * encoding; the URL is returned untouched when it has no query string or no
     * sensitive params. Use for `url`/`referrer` fields, which can otherwise
     * carry reset tokens, signed-URL signatures, `?api_key=`, etc.
     */
    public function scrubUrl(?string $url): ?string
    {
        if ($url === null || $url === '') {
            return $url;
        }

        $query = parse_url($url, PHP_URL_QUERY);
        if (! is_string($query) || $query === '') {
            return $url;
        }

        $scrubbed = $this->scrubQuery($query, $this->sensitiveFragments());
        if ($scrubbed === $query) {
            return $url;
        }

        $queryStart = mb_strpos($url, '?');
        if ($queryStart === false) {
            return $url;
        }

        $fragmentStart = mb_strpos($url, '#', $queryStart);
        $fragment = $fragmentStart !== false ? mb_substr($url, $fragmentStart) : '';

        return mb_substr($url, 0, $queryStart).'?'.$scrubbed.$fragment;
    }

    /**
     * Whether a route parameter is secret-bearing, judged by its NAME and, for
     * custom-key binding syntax such as `{invitation:token}`, by its BINDING
     * FIELD. The binding field matters because it is where the sensible name
     * lives in that syntax: the parameter is called `invitation`, and only the
     * field (`token`) says what the segment actually holds.
     *
     * Best-effort by nature: this is a substring test over a fragment list, so
     * a parameter named `{code}` or `{t}` is indistinguishable from any other.
     */
    public function isSensitiveRouteParameter(string $name, ?string $bindingField = null): bool
    {
        $fragments = [...$this->sensitiveFragments(), ...self::ROUTE_PARAMETER_KEYS];

        if ($this->isSensitive($name, $fragments)) {
            return true;
        }

        return $bindingField !== null
            && $bindingField !== ''
            && $this->isSensitive($bindingField, $fragments);
    }

    /**
     * The values of route parameters that {@see isSensitiveRouteParameter()}
     * judges secret-bearing, e.g. the `{token}` of `password/reset/{token}` or
     * the `{hash}` of `email/verify/{id}/{hash}`.
     *
     * Secrets in a URL PATH cannot be spotted by inspecting the path itself, so
     * the route definition is used as the oracle: the parameter names say which
     * segments are secret, whatever the (localized or custom) route looks like.
     * A framework adapter feeds its router's parameters in here and the result
     * to {@see scrubUrlPath()}. Values that are non-scalar or empty are skipped.
     *
     * @param  array<array-key, mixed>  $parameters  Raw route parameters, before model binding substituted objects.
     * @param  array<array-key, mixed>  $bindingFields  Parameter name => binding field.
     * @return array<int, string>
     */
    public function sensitiveRouteParameterValues(array $parameters, array $bindingFields = []): array
    {
        $values = [];

        foreach ($parameters as $name => $value) {
            if (! is_string($name)) {
                continue;
            }

            $bindingField = $bindingFields[$name] ?? null;

            if (! $this->isSensitiveRouteParameter($name, is_string($bindingField) ? $bindingField : null)) {
                continue;
            }

            if (! is_scalar($value)) {
                continue;
            }

            $value = (string) $value;

            if ($value !== '') {
                $values[] = $value;
            }
        }

        return array_values(array_unique($values));
    }

    /**
     * Replace every path segment that (once rawurldecoded) exactly equals one of
     * the given sensitive values with {@see REDACTION}, leaving all other
     * segments byte-for-byte intact. A value occurring in several segments is
     * redacted in each of them.
     *
     * @param  array<int, string>  $sensitiveValues
     */
    public function scrubPathSegments(string $path, array $sensitiveValues): string
    {
        if ($path === '' || $sensitiveValues === []) {
            return $path;
        }

        $segments = explode('/', $path);

        foreach ($segments as $index => $segment) {
            if ($segment === '') {
                continue;
            }

            if (in_array(rawurldecode($segment), $sensitiveValues, true)) {
                $segments[$index] = self::REDACTION;
            }
        }

        return implode('/', $segments);
    }

    /**
     * Apply {@see scrubPathSegments()} to the PATH component of a URL, leaving
     * the scheme, host, port, query and fragment exactly as they were, so it
     * composes with {@see scrubUrl()} (which redacts the query) without
     * re-encoding anything.
     *
     * Where the Laravel SDK resolves the sensitive segments from the matched
     * route, this SDK has no router to ask: the caller supplies the segment
     * values, typically from {@see sensitiveRouteParameterValues()}. Passing
     * null or an empty list means "query-only scrubbing", which is the correct
     * behaviour for a host that cannot say which segments are secret.
     *
     * @param  array<int, string>|null  $sensitiveValues
     */
    public function scrubUrlPath(?string $url, ?array $sensitiveValues = null): ?string
    {
        if ($url === null || $url === '' || $sensitiveValues === null || $sensitiveValues === []) {
            return $url;
        }

        $pathStart = $this->pathOffset($url);
        $pathEnd = mb_strlen($url);

        foreach (['?', '#'] as $delimiter) {
            $position = mb_strpos($url, $delimiter, $pathStart);

            if ($position !== false && $position < $pathEnd) {
                $pathEnd = $position;
            }
        }

        $path = mb_substr($url, $pathStart, $pathEnd - $pathStart);
        $scrubbed = $this->scrubPathSegments($path, $sensitiveValues);

        if ($scrubbed === $path) {
            return $url;
        }

        return mb_substr($url, 0, $pathStart).$scrubbed.mb_substr($url, $pathEnd);
    }

    /**
     * Redact `key=value` / `key: value` / `key => value` pairs in a free-form
     * string when the key contains a sensitive fragment. Partial, best-effort
     * defense-in-depth for strings we cannot structure (e.g. exception stack
     * traces): it catches query-string-like and key/value leakage, but not
     * positional secret arguments that carry no key.
     */
    public function scrubString(string $value): string
    {
        if ($value === '') {
            return $value;
        }

        $alternation = implode('|', array_map(
            static fn (string $fragment): string => preg_quote($fragment, '/'),
            $this->sensitiveFragments()
        ));

        // key-token (containing a sensitive fragment) + separator (= : =>) + value.
        $pattern = '/(["\']?[\w.\-]*(?:'.$alternation.')[\w.\-]*["\']?\s*(?:=>|[:=])\s*)(["\']?)([^"\'\s,;&)}]+)\2/i';

        $result = preg_replace_callback($pattern, static function (array $matches): string {
            return $matches[1].$matches[2].self::REDACTION.$matches[2];
        }, $value);

        return $result ?? $value;
    }

    /**
     * Offset at which the path component of a URL starts: after `scheme://host`
     * (and any port) for an absolute URL, or 0 for a relative one. Returns the
     * string length when an absolute URL has no path at all.
     */
    private function pathOffset(string $url): int
    {
        $schemeEnd = mb_strpos($url, '://');

        if ($schemeEnd === false) {
            return 0;
        }

        $pathStart = mb_strpos($url, '/', $schemeEnd + 3);

        return $pathStart === false ? mb_strlen($url) : $pathStart;
    }

    /**
     * Redact the values of sensitive keys in a raw query string, leaving every
     * other pair byte-for-byte intact.
     *
     * @param  array<int, string>  $fragments
     */
    private function scrubQuery(string $query, array $fragments): string
    {
        $pairs = explode('&', $query);

        foreach ($pairs as $index => $pair) {
            if ($pair === '') {
                continue;
            }

            $equals = mb_strpos($pair, '=');
            $rawKey = $equals === false ? $pair : mb_substr($pair, 0, $equals);

            if ($this->isSensitive(urldecode($rawKey), $fragments)) {
                $pairs[$index] = $rawKey.'='.self::REDACTION;
            }
        }

        return implode('&', $pairs);
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @param  array<int, string>  $fragments
     * @return array<array-key, mixed>
     */
    private function scrubArray(array $data, array $fragments): array
    {
        foreach ($data as $key => $value) {
            if (is_string($key) && $this->isSensitive($key, $fragments)) {
                $data[$key] = self::REDACTION;

                continue;
            }

            if (is_array($value)) {
                $data[$key] = $this->scrubArray($value, $fragments);
            }
        }

        return $data;
    }

    /**
     * Recursively apply {@see scrubUrl()} to every string value that looks like
     * an absolute http(s) URL, leaving all other values untouched. Operates on
     * the already-depth-bounded output of {@see DataSanitizer}.
     */
    private function scrubUrlValues(mixed $data): mixed
    {
        if (is_string($data)) {
            return str_starts_with($data, 'http://') || str_starts_with($data, 'https://')
                ? ($this->scrubUrl($data) ?? $data)
                : $data;
        }

        if (is_array($data)) {
            foreach ($data as $key => $value) {
                $data[$key] = $this->scrubUrlValues($value);
            }
        }

        return $data;
    }

    /**
     * @param  array<int, string>  $fragments
     */
    private function isSensitive(string $key, array $fragments): bool
    {
        $haystack = mb_strtolower($key);

        foreach ($fragments as $fragment) {
            if (str_contains($haystack, $fragment)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<int, string>
     */
    private function sensitiveFragments(): array
    {
        if ($this->fragments !== null) {
            return $this->fragments;
        }

        $extra = $this->config->get('scrubbing.extra_keys', []);

        if (! is_array($extra)) {
            $extra = [];
        }

        $extra = array_map(
            static fn (mixed $fragment): string => mb_strtolower(is_scalar($fragment) ? (string) $fragment : ''),
            $extra
        );

        $extra = array_filter($extra, static fn (string $fragment): bool => $fragment !== '');

        return $this->fragments = array_values(array_unique([...self::DEFAULT_KEYS, ...$extra]));
    }
}
