<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use Ranetrace\Php\Config;
use Throwable;
use UnexpectedValueException;

/**
 * Redacts values stored under sensitive keys before telemetry leaves the host.
 *
 * Applied to log context/extra, event properties, JS breadcrumbs and exception
 * traces so that a secret a developer accidentally logged never reaches the
 * Ranetrace backend. Matching is a case-insensitive substring test on the key
 * name. The built-in fragment list is always applied and can be extended (never
 * shrunk) via the `scrubbing.extra_keys` config value.
 *
 * This is the ONE scrubber both SDKs use. `ranetrace/ranetrace-laravel` used to
 * keep a copy of it; the copy is gone, and the router knowledge that was the
 * copy's whole reason to exist now arrives through the `$sensitiveValues`
 * callable seam described on {@see scrubDeep()}. The redaction semantics are the
 * privacy promise the two SDKs share, so there is deliberately nowhere left for
 * them to drift.
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
     * How many characters of a key token may precede the sensitive fragment
     * inside it, in {@see scrubString()}. Bounding this is what keeps the
     * pattern's cost linear; see that method for why, and for what it costs.
     */
    private const int MAX_KEY_PREFIX = 64;

    /**
     * What ends a bare token: the whitespace `\s` means, a quote, and the
     * characters that end a pair in a query string, an argument list or an
     * array.
     */
    private const string BARE_VALUE_STOPS = "\"' \t\n\v\f\r,;&)]}";

    /**
     * Built-in fragments merged with the user-configured extensions, resolved
     * once per instance.
     *
     * @var array<int, string>|null
     */
    private ?array $fragments = null;

    /**
     * {@see anchorPattern()}, built once per instance.
     */
    private ?string $anchorPattern = null;

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
     * PATH is scrubbed only for the segment values the caller declares secret,
     * because a path segment carries no marker saying "this is a token" and
     * this library has no router to ask. Leaving that unanswered means a reset
     * link recorded as a navigation breadcrumb keeps its live token while the
     * top-level `url` field of the same item is path-redacted: the same secret
     * redacted in one field and shipped in another.
     *
     * $sensitiveValues answers the question in one of three ways:
     *
     * - `null`: nobody can say, so the path is left alone (query-only).
     * - a list of strings: those segment values are secret in EVERY URL found.
     *   What a plain-PHP host has, typically from
     *   {@see sensitiveRouteParameterValues()} for the request being handled.
     * - a callable: called with each URL-shaped value in turn, returning the
     *   segment values that are secret in THAT url. This is the seam a host
     *   with a router needs, because free-form data holds URLs from other
     *   requests than the current one (a breadcrumb recorded on the previous
     *   page), and only a per-URL lookup can say what those hold. The Laravel
     *   SDK passes its `RouteSecretResolver`.
     *
     * Intended for free-form, untrusted breadcrumb/context data. Composes with
     * the `mixed` return of {@see DataSanitizer::sanitizeForSerialization()},
     * which has already bounded the recursion depth.
     *
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitiveValues
     */
    public function scrubDeep(mixed $data, array|callable|null $sensitiveValues = null): mixed
    {
        return $this->scrubUrlValues($this->scrub($data), $sensitiveValues);
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
     * $sensitiveValues takes the three forms {@see scrubDeep()} documents; a
     * callable is resolved against this URL. Null, an empty list or a callable
     * that answers with neither means "query-only scrubbing", which is the
     * correct behaviour for a host that cannot say which segments are secret.
     *
     * The FRAGMENT is run through {@see scrubPathSegments()} as well, because a
     * single-page app routes in it: `/app#/reset/abc123` puts the token in a
     * path-shaped fragment. Segment matching is an exact whole-segment compare,
     * so this is safe on a fragment of any shape.
     *
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitiveValues
     */
    public function scrubUrlPath(?string $url, array|callable|null $sensitiveValues = null): ?string
    {
        if ($url === null || $url === '') {
            return $url;
        }

        $sensitiveValues = $this->resolveSensitiveValues($url, $sensitiveValues);

        if ($sensitiveValues === []) {
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
     * A regex finds each key and its separator (the anchor), and the value
     * after it is read by hand, because a code value has to balance brackets
     * and one pattern cannot do that cheaply. See {@see anchorPattern()} for
     * what an anchor is and why the pattern stays linear.
     *
     * The value after an anchor takes one of three shapes:
     *
     * - A quoted value is redacted whole. It runs to its matching closing
     *   quote, past spaces, commas and the other quote, with backslash escapes
     *   skipped. Without a closing quote it runs to the end of the line, never
     *   further. An empty one (`''`) holds nothing and is left alone.
     * - A code value keeps its code byte-for-byte and loses only the bodies of
     *   the string literals inside it, since in `'password' => Hash::make('x')`
     *   the literal is the secret and the rest is what makes the line worth
     *   reading. {@see startsCodeValue()} says what starts one, and
     *   {@see redactCodeValue()} where it ends.
     * - Anything else is a bare token, redacted up to whitespace, a quote or
     *   `,;&)]}`, after an optional `Bearer`, `Basic` or `Digest` scheme that is
     *   kept. `true`, `null`, a number or a constant is a bare token too: it is
     *   redacted, which costs nothing readable and needs no list of literals.
     *
     * Fails closed anyway. PCRE can still give up (a pathological input, a
     * lowered `pcre.backtrack_limit`), and returning the input then would ship
     * the very string we were asked to redact, so the whole value becomes the
     * placeholder instead: losing the string beats leaking it. The give-up is
     * written to the internal log so a scrubber that has started swallowing
     * strings is visible rather than silent.
     */
    public function scrubString(string $value): string
    {
        if ($value === '') {
            return $value;
        }

        try {
            return $this->scrubText($value);
        } catch (UnexpectedValueException $failure) {
            $this->log->warning('Secret scrubbing of a free-form string failed, so the whole string was redacted.', [
                'error' => $failure->getMessage(),
                'length' => mb_strlen($value),
            ]);

            return self::REDACTION;
        }
    }

    /**
     * {@see scrubString()} without the fail-closed wrapper.
     *
     * Offsets here are byte offsets, as PCRE reports them, hence `8bit` on
     * every length and substring. Every boundary the scrubber cuts at is an
     * ASCII character, so a multibyte character is never split.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function scrubText(string $text): string
    {
        $length = mb_strlen($text, '8bit');
        $scrubbed = '';
        $offset = 0;

        while ($offset < $length) {
            $found = preg_match($this->anchorPattern(), $text, $matches, PREG_OFFSET_CAPTURE | PREG_UNMATCHED_AS_NULL, $offset);

            if ($found === false) {
                throw new UnexpectedValueException(preg_last_error_msg());
            }

            if ($found === 0) {
                break;
            }

            $anchorEnd = $matches[0][1] + mb_strlen((string) $matches[0][0], '8bit');
            $value = match (true) {
                ($matches['call'][1] ?? -1) >= 0 => $this->redactCodeValue($text, $anchorEnd, true),
                ($matches['comma'][1] ?? -1) >= 0 => $this->redactQuotedValue($text, $anchorEnd),
                default => $this->redactValue($text, $anchorEnd),
            };

            $scrubbed .= mb_substr($text, $offset, $anchorEnd - $offset, '8bit');
            $offset = $anchorEnd;

            if ($value !== null) {
                [$replacement, $offset] = $value;
                $scrubbed .= $replacement;
            }
        }

        return $scrubbed.mb_substr($text, $offset, null, '8bit');
    }

    /**
     * The pattern that finds where a secret value starts: a sensitive key and
     * the separator after it.
     *
     * - A key is a token of `[\w.\-]` holding a sensitive fragment, optionally
     *   quoted and optionally closing a subscript: `password=`, `"api_key":`,
     *   `'token' =>`, `$config['db']['password'] =`.
     * - The separator is `=>`, `:`, `=`, `.=`, `??=` or a comparison (`==`,
     *   `===`, `!=`, `!==`), held atomically so `=>` can never be taken as `=`
     *   followed by a value of `>`. `::` is not a separator, so
     *   `PersonalAccessToken::findToken()` stays readable.
     * - A quoted key followed by `,` and a quote is an anchor too:
     *   `define('STRIPE_SECRET', '...')`, `env('API_KEY', '...')`. Its value is
     *   read as a quoted value only.
     * - A call to a function or method whose name holds a sensitive fragment
     *   is an anchor as well, up to its `(`: `Stripe::setApiKey(`,
     *   `$client->setToken(`, `Http::withToken(`. What follows is read as a code
     *   value inside the call's parentheses, so its literals are redacted, every
     *   argument of it, and a call with no literal stays as written. A
     *   credential passed to a call whose name says nothing about it, such as
     *   `new PDO($dsn, 'root', 'hunter2')`, is not recognised.
     *
     * Three details are load-bearing, all of them about cost. It runs on stack
     * traces and log messages, which are the longest, least structured strings
     * the SDK ever touches, and the naive spelling
     * `[\w.\-]*(?:fragment)[\w.\-]*` is quadratic on a long word-character run:
     * every start position re-tries every prefix length. On a 50k run that is
     * billions of steps, which PCRE ends by hitting its backtrack limit.
     *
     * - `(?<![\w.\-])` means a match can only START where a key token can, so a
     *   long word run is entered once instead of once per character. This is
     *   what turns the scan linear.
     * - The prefix is bounded to {@see MAX_KEY_PREFIX} characters. It exists to
     *   keep the full key name in the anchor, and no real key name (`stripe_`,
     *   `user_api_`) comes close. A sensitive fragment buried further than that
     *   into one unbroken token is not recognised, which is the one case this
     *   spelling gives up on deliberately.
     * - Every other repeat is possessive. The characters that can follow a key
     *   are all outside `[\w.\-]`, so giving characters back can never help it
     *   match: the backtracking it would do is pure waste.
     */
    private function anchorPattern(): string
    {
        if ($this->anchorPattern !== null) {
            return $this->anchorPattern;
        }

        $alternation = implode('|', array_map(
            static fn (string $fragment): string => preg_quote($fragment, '/'),
            $this->sensitiveFragments()
        ));

        $key = '[\w.\-]{0,'.self::MAX_KEY_PREFIX.'}(?:'.$alternation.')[\w.\-]*+';
        $separator = '(?>=>|:(?!:)|!==?|===?|\.=|\?\?=|=)';

        return $this->anchorPattern = '/(?<![\w.\-])(?:'
            .'["\']?'.$key.'["\']?\]?\s*+'.$separator.'\s*+'
            .'|(?<comma>["\']'.$key.'["\']\s*+,\s*+)(?=["\'])'
            .')|(?<!\w)(?<call>\w{0,'.self::MAX_KEY_PREFIX.'}(?:'.$alternation.')\w*+\()/i';
    }

    /**
     * The redacted form of the value that starts at $offset, and the offset
     * just past it, or null when nothing there is a value.
     *
     * @return array{0: string, 1: int}|null
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function redactValue(string $text, int $offset): ?array
    {
        $scheme = $this->matchAt('/\G(?:bearer|basic|digest)\s++(?![,;&)\]}]|$)/i', $text, $offset);
        $start = $offset + mb_strlen($scheme, '8bit');
        $first = $text[$start] ?? '';

        if ($first === '') {
            return null;
        }

        if ($first === '"' || $first === "'") {
            $quoted = $this->redactQuotedValue($text, $start);

            return $quoted === null ? null : [$scheme.$quoted[0], $quoted[1]];
        }

        $heredoc = $this->matchAt('/\G<<<[ \t]*+(["\']?)[A-Za-z_]\w*+\1/', $text, $start);

        if ($heredoc !== '') {
            return [$scheme.$heredoc, $start + mb_strlen($heredoc, '8bit')];
        }

        if ($this->startsCodeValue($text, $start)) {
            [$code, $end] = $this->redactCodeValue($text, $start, false);

            return [$scheme.$code, $end];
        }

        $bareLength = strcspn($text, self::BARE_VALUE_STOPS, $start);

        if ($bareLength === 0) {
            return null;
        }

        return [$scheme.self::REDACTION, $start + $bareLength];
    }

    /**
     * Whether a code value starts at $offset: a variable, an opening bracket,
     * an attribute, `new`, `clone`, `fn`, `function`, `static` or `match`, or a name
     * (namespaced with `\` or chained with `.`) directly followed by `(`, `::`,
     * `->` or `?->`, optionally behind one `@` or `!`.
     *
     * A `$` counts only before a character a variable name can start with, so
     * a bcrypt hash such as `$2y$10$...` stays a bare token and is redacted.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function startsCodeValue(string $text, int $offset): bool
    {
        $name = '[A-Za-z_\x80-\xff][\w\x80-\xff]*+';

        return $this->matchAt(
            '/\G[@!]?+(?:\$[A-Za-z_\x80-\xff{$]|[\[({]|#\[|(?:new|clone|fn|function|static|match)(?=[\s(])'
            .'|\\\\?'.$name.'(?:[\\\\.]'.$name.')*+(?:\(|::|\??->))/i',
            $text,
            $offset,
        ) !== '';
    }

    /**
     * A code value with the body of every string literal in it redacted, and
     * the offset just past it.
     *
     * The value ends at the end of its line, at a closing bracket that has no
     * opening one inside the value (for a call, the one that closes it), at a
     * `,` (not inside a call, where it only separates arguments) or `;` outside
     * every bracket, or where a `//`, `/*` or `#` comment or a `?>` starts. A
     * literal runs as a quoted value does, so a comma, bracket or comment
     * marker inside one is never taken for the end. This is one pass over the
     * value: each step jumps to the next character that can matter.
     *
     * @return array{0: string, 1: int}
     */
    private function redactCodeValue(string $text, int $offset, bool $insideCall): array
    {
        $length = mb_strlen($text, '8bit');
        $redacted = '';
        $kept = $offset;
        $depth = 0;
        $position = $offset;

        while (true) {
            $position += strcspn($text, "\"'()[]{},;/#?\r\n", $position);

            if ($position >= $length) {
                break;
            }

            $character = $text[$position];
            $next = $text[$position + 1] ?? '';

            if ($character === '"' || $character === "'") {
                [$bodyEnd, $closed] = $this->quotedBodyEnd($text, $position);

                if ($bodyEnd > $position + 1) {
                    $redacted .= mb_substr($text, $kept, $position + 1 - $kept, '8bit').self::REDACTION;
                    $kept = $bodyEnd;
                }

                $position = $closed ? $bodyEnd + 1 : $bodyEnd;

                continue;
            }

            if ($character === "\r" || $character === "\n") {
                break;
            }

            if ($character === '(' || $character === '[' || $character === '{') {
                $depth++;
            } elseif ($character === ')' || $character === ']' || $character === '}') {
                if ($depth === 0) {
                    break;
                }

                $depth--;
            } elseif ($depth === 0 && ($character === ';' || ($character === ',' && ! $insideCall))) {
                break;
            } elseif (($character === '/' && ($next === '/' || $next === '*'))
                || ($character === '#' && $next !== '[')
                || ($character === '?' && $next === '>')) {
                break;
            }

            $position++;
        }

        return [$redacted.mb_substr($text, $kept, $position - $kept, '8bit'), $position];
    }

    /**
     * A quoted value that starts at $offset, redacted whole with its quotes
     * kept, and the offset just past it, or null when its body is empty.
     *
     * @return array{0: string, 1: int}|null
     */
    private function redactQuotedValue(string $text, int $offset): ?array
    {
        [$bodyEnd, $closed] = $this->quotedBodyEnd($text, $offset);

        if ($bodyEnd === $offset + 1) {
            return null;
        }

        $quote = $text[$offset];

        return $closed
            ? [$quote.self::REDACTION.$quote, $bodyEnd + 1]
            : [$quote.self::REDACTION, $bodyEnd];
    }

    /**
     * Where the body of the string literal opened at $offset ends, and whether
     * a closing quote ends it. A backslash escapes the character after it; the
     * body ends unclosed at a line break or the end of the string.
     *
     * @return array{0: int, 1: bool}
     */
    private function quotedBodyEnd(string $text, int $offset): array
    {
        $quote = $text[$offset];
        $length = mb_strlen($text, '8bit');
        $position = $offset + 1;

        while (true) {
            $position += strcspn($text, $quote."\\\r\n", $position);

            if ($position >= $length) {
                return [$length, false];
            }

            $character = $text[$position];

            if ($character === $quote) {
                return [$position, true];
            }

            $escaped = $text[$position + 1] ?? '';

            if ($character !== '\\' || $escaped === '' || $escaped === "\r" || $escaped === "\n") {
                return [$position, false];
            }

            $position += 2;
        }
    }

    /**
     * What $pattern, anchored with `\G`, matches at $offset, or `''`.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function matchAt(string $pattern, string $text, int $offset): string
    {
        $found = preg_match($pattern, $text, $matches, 0, $offset);

        if ($found === false) {
            throw new UnexpectedValueException(preg_last_error_msg());
        }

        return $found === 1 ? $matches[0] : '';
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
     * values $sensitiveValues declares secret-bearing, in whichever of its three
     * forms; a callable is asked about each URL separately.
     *
     * A callable is resolved against the ORIGINAL value rather than the
     * query-scrubbed one, so a host that matches the URL against its routes
     * sees what the browser actually recorded. Redacting the query first cannot
     * change which path segments a route names, but it can change the string a
     * router is handed.
     *
     * Operates on the already-depth-bounded output of {@see DataSanitizer}.
     *
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitiveValues
     */
    private function scrubUrlValues(mixed $data, array|callable|null $sensitiveValues): mixed
    {
        if (is_string($data)) {
            if (! $this->isScrubbableUrl($data)) {
                return $data;
            }

            $resolved = $this->resolveSensitiveValues($data, $sensitiveValues);
            $scrubbed = $this->scrubUrl($data) ?? $data;

            return $this->scrubUrlPath($scrubbed, $resolved) ?? $scrubbed;
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
     * The secret-bearing segment values for one URL, whichever of the three
     * forms of $sensitiveValues the caller supplied.
     *
     * A callable that throws is treated as "cannot say" rather than allowed to
     * escape: it is host code reaching for a router mid-capture, and a capture
     * path must never break the application it is watching. The result is
     * query-only scrubbing for that value, which is what a host with no router
     * gets anyway.
     *
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitiveValues
     * @return array<int, string>
     */
    private function resolveSensitiveValues(string $url, array|callable|null $sensitiveValues): array
    {
        if ($sensitiveValues === null) {
            return [];
        }

        if (is_array($sensitiveValues)) {
            return $sensitiveValues;
        }

        try {
            $resolved = $sensitiveValues($url);
        } catch (Throwable $failure) {
            $this->log->warning('Resolving the sensitive path segments of a URL failed, so its path was left unscrubbed.', [
                'error' => $failure->getMessage(),
            ]);

            return [];
        }

        return is_array($resolved) ? $resolved : [];
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
