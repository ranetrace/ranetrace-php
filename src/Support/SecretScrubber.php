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
 * they must not drift. Only the collaborator lookup changed, from Laravel
 * facades to an injected {@see Config} and {@see InternalLogger}.
 */
final class SecretScrubber implements Scrubber
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
     * Characters allowed in the path of a relative reference: RFC 3986 pchar
     * (unreserved, percent-encoded, sub-delims, `:` and `@`) plus the separator
     * itself. Deliberately narrower than "anything without whitespace", since
     * it is what keeps prose, JSON and code snippets out of the URL path.
     */
    private const string URL_PATH_CHARS = "A-Za-z0-9._~%!$&'()*+,;=:@/-";

    /**
     * Characters allowed in a query parameter NAME: pchar without `=` (which
     * separates the pair) and without `&` (which separates pairs).
     */
    private const string URL_KEY_CHARS = "A-Za-z0-9._~%!$'()*+,;:@-";

    /**
     * Characters allowed in a query parameter VALUE: as the name, plus `=` and
     * `/`, both legal unencoded in a query.
     */
    private const string URL_VALUE_CHARS = "A-Za-z0-9._~%!$'()*+,;:@=/-";

    /**
     * Built-in fragments merged with the user-configured extensions, resolved
     * once per instance.
     *
     * @var array<int, string>|null
     */
    private ?array $fragments = null;

    public function __construct(
        private readonly Config $config,
        private readonly Diagnostics $log,
    ) {}

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
     * Like {@see scrub()} (key-based redaction), but ALSO scrubs secrets inside
     * URL-shaped string VALUES, catching a secret in an innocuously-keyed URL
     * (e.g. a breadcrumb `data.endpoint` of `https://api/x?token=…`) that
     * key-based scrubbing alone would miss.
     *
     * Both halves of a URL can carry one. The QUERY is always scrubbed. The
     * PATH is scrubbed only when the caller supplies the segment values that
     * are secret, because a path segment carries no marker saying "this is a
     * token" and this SDK has no router to ask — the Laravel SDK resolves them
     * from the matched route. A host that knows its own routes should pass
     * {@see sensitiveRouteParameterValues()} here, otherwise a reset link
     * recorded as a navigation breadcrumb keeps its live token: the top-level
     * `url` field is already path-redacted, so leaving this null redacts the
     * same secret in one field and ships it in another.
     *
     * Intended for free-form, untrusted breadcrumb/context data. Composes with
     * the `mixed` return of {@see DataSanitizer::sanitizeForSerialization()},
     * which has already bounded the recursion depth.
     *
     * @param  array<int, string>|null  $sensitiveValues
     */
    public function scrubDeep(mixed $data, ?array $sensitiveValues = null): mixed
    {
        return $this->scrubUrlValues($this->scrub($data), $sensitiveValues ?? []);
    }

    /**
     * Redact sensitive query-string parameters within a URL, preserving the
     * scheme, host and path. Non-sensitive params keep their exact encoding;
     * the URL is returned untouched when it carries no sensitive params. Use
     * for `url`/`referrer` fields, which can otherwise carry reset tokens,
     * signed-URL signatures, `?api_key=`, etc.
     *
     * The FRAGMENT is scrubbed too, but only when it is itself query-shaped: an
     * OAuth implicit-flow redirect comes back as `/callback#access_token=…`, so
     * a fragment can carry exactly the secret the query does. A fragment of any
     * other shape (an anchor, an SPA hash route) is returned byte-for-byte,
     * since {@see scrubQuery()} would otherwise rewrite prose into pairs.
     */
    public function scrubUrl(?string $url): ?string
    {
        if ($url === null || $url === '') {
            return $url;
        }

        $fragmentStart = mb_strpos($url, '#');
        $withoutFragment = $fragmentStart === false ? $url : mb_substr($url, 0, $fragmentStart);
        $fragment = $fragmentStart === false ? '' : mb_substr($url, $fragmentStart + 1);

        $scrubbedUrl = $this->scrubUrlQuery($withoutFragment);
        $scrubbedFragment = $this->isQueryShaped($fragment)
            ? $this->scrubQuery($fragment, $this->sensitiveFragments())
            : $fragment;

        if ($scrubbedUrl === $withoutFragment && $scrubbedFragment === $fragment) {
            return $url;
        }

        return $fragmentStart === false ? $scrubbedUrl : $scrubbedUrl.'#'.$scrubbedFragment;
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
     * the scheme, host, port and query exactly as they were, so it composes
     * with {@see scrubUrl()} (which redacts the query) without re-encoding
     * anything.
     *
     * Where the Laravel SDK resolves the sensitive segments from the matched
     * route, this SDK has no router to ask: the caller supplies the segment
     * values, typically from {@see sensitiveRouteParameterValues()}. Passing
     * null or an empty list means "query-only scrubbing", which is the correct
     * behaviour for a host that cannot say which segments are secret.
     *
     * The FRAGMENT is run through {@see scrubPathSegments()} as well, because a
     * single-page app routes in it: `/app#/reset/abc123` puts the token in a
     * path-shaped fragment. Segment matching is an exact whole-segment compare,
     * so this is safe on a fragment of any shape.
     *
     * @param  array<int, string>|null  $sensitiveValues
     */
    public function scrubUrlPath(?string $url, ?array $sensitiveValues = null): ?string
    {
        if ($url === null || $url === '' || $sensitiveValues === null || $sensitiveValues === []) {
            return $url;
        }

        $fragmentStart = mb_strpos($url, '#');
        $withoutFragment = $fragmentStart === false ? $url : mb_substr($url, 0, $fragmentStart);
        $fragment = $fragmentStart === false ? '' : mb_substr($url, $fragmentStart + 1);

        $pathStart = $this->pathOffset($withoutFragment);
        $pathEnd = mb_strpos($withoutFragment, '?', $pathStart);

        if ($pathEnd === false) {
            $pathEnd = mb_strlen($withoutFragment);
        }

        $path = mb_substr($withoutFragment, $pathStart, $pathEnd - $pathStart);
        $scrubbedPath = $this->scrubPathSegments($path, $sensitiveValues);
        $scrubbedFragment = $this->scrubPathSegments($fragment, $sensitiveValues);

        if ($scrubbedPath === $path && $scrubbedFragment === $fragment) {
            return $url;
        }

        return mb_substr($withoutFragment, 0, $pathStart)
            .$scrubbedPath
            .mb_substr($withoutFragment, $pathEnd)
            .($fragmentStart === false ? '' : '#'.$scrubbedFragment);
    }

    /**
     * Redact `key=value` / `key: value` / `key => value` pairs in a free-form
     * string when the key contains a sensitive fragment. Partial, best-effort
     * defense-in-depth for strings we cannot structure (e.g. exception stack
     * traces): it catches query-string-like and key/value leakage, but not
     * positional secret arguments that carry no key.
     *
     * Fails closed. The pattern backtracks super-linearly on a long run of word
     * characters, so PCRE can hit its backtrack limit and give up. Returning the
     * input then would ship the very string we were asked to redact, so the
     * whole value becomes the placeholder instead: losing the string beats
     * leaking it. The give-up is written to the internal log so a scrubber that
     * has started swallowing strings is visible rather than silent.
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

        if ($result === null) {
            $this->log->warning('Secret scrubbing of a free-form string failed, so the whole string was redacted.', [
                'error' => preg_last_error_msg(),
                'length' => mb_strlen($value),
            ]);

            return self::REDACTION;
        }

        return $result;
    }

    /**
     * Offset at which the path component of a URL starts: after the authority
     * (`scheme://host`, any port, and the protocol-relative `//host` form) for
     * an absolute reference, or 0 for a relative one. Returns the string length
     * when an absolute URL has no path at all.
     *
     * The authority is recognised only at the START of the string. An
     * unanchored search for `://` finds the one inside
     * `/reset-password/TOKEN?next=https://app.test/dashboard` and puts the path
     * window in the middle of the query, which left the live token in the part
     * nothing then inspected.
     */
    private function pathOffset(string $url): int
    {
        if (preg_match('#^(?:[A-Za-z][A-Za-z0-9+.\-]*:)?//[^/?\#]*#', $url, $matches) !== 1) {
            return 0;
        }

        return mb_strlen($matches[0]);
    }

    /**
     * Redact the sensitive query parameters of a fragment-free URL, leaving
     * every other byte of it exactly as it was.
     */
    private function scrubUrlQuery(string $url): string
    {
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

        return mb_substr($url, 0, $queryStart).'?'.$scrubbed;
    }

    /**
     * Whether a string is a run of `key=value` pairs, the shape {@see scrubQuery()}
     * is safe to rewrite. Used for the query of a relative reference and for a
     * fragment, both of which are free-form until proven otherwise.
     */
    private function isQueryShaped(string $value): bool
    {
        $pair = '['.self::URL_KEY_CHARS.']+=['.self::URL_VALUE_CHARS.']*';

        return preg_match('#^'.$pair.'(?:&'.$pair.')*$#', $value) === 1;
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
     * a URL, leaving all other values untouched. A relative reference counts:
     * a signed download link recorded as `/exports/42/download?signature=…`
     * carries its secret in exactly the same place an absolute one does.
     *
     * The QUERY is always scrubbed. The PATH is scrubbed only for the segment
     * values the caller declared secret-bearing, since this SDK has no router
     * to resolve them from; an empty list means query-only, which is the
     * correct behaviour for a host that cannot say which segments are secret.
     *
     * Operates on the already-depth-bounded output of {@see DataSanitizer}.
     *
     * @param  array<int, string>  $sensitiveValues
     */
    private function scrubUrlValues(mixed $data, array $sensitiveValues): mixed
    {
        if (is_string($data)) {
            if (! $this->isScrubbableUrl($data)) {
                return $data;
            }

            $scrubbed = $this->scrubUrl($data) ?? $data;

            return $this->scrubUrlPath($scrubbed, $sensitiveValues) ?? $scrubbed;
        }

        if (is_array($data)) {
            foreach ($data as $key => $value) {
                $data[$key] = $this->scrubUrlValues($value, $sensitiveValues);
            }
        }

        return $data;
    }

    /**
     * Whether a string value should be treated as a URL and scrubbed.
     *
     * Absolute http(s) URLs always qualify. A relative reference qualifies only
     * on a strict shape, because these values are free-form: it must carry a
     * path separator or a query, must not contain a character that only turns
     * up in prose, JSON or code, and its query, when it has one, must be a run
     * of `key=value` pairs. That structure is what keeps a JSON payload or a
     * code snippet with a question mark in it out of {@see scrubUrl()}, whose
     * rewrite would otherwise truncate the value at its first `?`.
     */
    private function isScrubbableUrl(string $value): bool
    {
        if ($value === '') {
            return false;
        }

        if (str_starts_with($value, 'http://') || str_starts_with($value, 'https://')) {
            return true;
        }

        if (preg_match('/[\s"`{}<>\\\\|^\[\]]/', $value) === 1) {
            return false;
        }

        if (! str_contains($value, '/') && ! str_contains($value, '?')) {
            return false;
        }

        [$beforeFragment] = explode('#', $value, 2);
        [$path, $query] = array_pad(explode('?', $beforeFragment, 2), 2, null);

        if (preg_match('#^(?:\.{0,2}/)?['.self::URL_PATH_CHARS.']*$#', $path) !== 1) {
            return false;
        }

        if ($query === null) {
            return true;
        }

        return $this->isQueryShaped($query);
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
