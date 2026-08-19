<?php

declare(strict_types=1);

namespace Ranetrace\Php\Errors;

/**
 * Everything about the host that an error item needs and a throwable does not
 * carry: the request it happened in, whether the process is a console one, and
 * which URL path segments hold a secret.
 *
 * The values here are RAW. Truncation, masking and redaction all happen in
 * {@see PayloadBuilder}, so the two SDKs cannot bound the same field
 * differently: what a host supplies is what it observed, not what it decided to
 * ship.
 *
 * Two ways in, because there are two kinds of host:
 *
 * - {@see fromServer()} reads a `$_SERVER`-shaped array, which is all a plain
 *   PHP host has.
 * - {@see provided()} takes each value as stated, which is what a framework
 *   adapter has: `ranetrace/ranetrace-laravel` hands over its `Request`'s
 *   headers, full URL and method, its own console detection, and the
 *   secret-bearing path segments its ROUTER resolved. A superglobal cannot
 *   answer the last of those, which is why the seam exists at all.
 */
final readonly class ErrorContext
{
    /**
     * @param  array<string, mixed>|null  $headers  Header name (lowercase) => value or values.
     * @param  string|null  $url  The full URL of the request, unscrubbed.
     * @param  string|null  $consoleCommand  The command line as one string, unscrubbed.
     * @param  array<int, mixed>|null  $consoleArguments  The command line as an argv list, unbounded.
     * @param  string|null  $timestamp  ISO 8601 capture time. Null lets the builder read the clock, which a host with a freezable clock of its own will not want.
     * @param  array<int, string>|null  $sensitivePathValues  Path segment values to redact from {@see $url}. Null means query-only scrubbing.
     * @param  (callable(string): (array<int, string>|null))|null  $refererPathValues  The same question asked about an arbitrary URL, for the `Referer` header, which describes a request that is not this one.
     */
    private function __construct(
        public bool $isConsole,
        public ?array $headers = null,
        public ?string $url = null,
        public ?string $method = null,
        public ?string $consoleCommand = null,
        public ?array $consoleArguments = null,
        public ?string $timestamp = null,
        public ?array $sensitivePathValues = null,
        private mixed $refererPathValues = null,
    ) {}

    /**
     * Derive the request and console context from a `$_SERVER`-shaped array.
     *
     * `$isConsole` is passed rather than read from `PHP_SAPI` so the caller owns
     * the decision, and so both branches are reachable from a test suite, which
     * always runs under the CLI SAPI.
     *
     * @param  array<array-key, mixed>  $server
     * @param  array<int, string>|null  $sensitivePathValues
     */
    public static function fromServer(array $server, bool $isConsole, ?array $sensitivePathValues = null): self
    {
        $argv = self::argv($server);

        return new self(
            isConsole: $isConsole,
            headers: self::headers($server),
            url: self::url($server),
            method: self::serverString($server, 'REQUEST_METHOD'),
            consoleCommand: $argv === [] ? null : implode(' ', $argv),
            consoleArguments: $argv,
            sensitivePathValues: $sensitivePathValues,
        );
    }

    /**
     * State every value, for a host that has a request abstraction of its own.
     *
     * @param  array<string, mixed>|null  $headers
     * @param  array<int, mixed>|null  $consoleArguments
     * @param  array<int, string>|null  $sensitivePathValues
     * @param  (callable(string): (array<int, string>|null))|null  $refererPathValues
     */
    public static function provided(
        bool $isConsole,
        ?array $headers = null,
        ?string $url = null,
        ?string $method = null,
        ?string $consoleCommand = null,
        ?array $consoleArguments = null,
        ?string $timestamp = null,
        ?array $sensitivePathValues = null,
        ?callable $refererPathValues = null,
    ): self {
        return new self(
            isConsole: $isConsole,
            headers: $headers,
            url: $url,
            method: $method,
            consoleCommand: $consoleCommand,
            consoleArguments: $consoleArguments,
            timestamp: $timestamp,
            sensitivePathValues: $sensitivePathValues,
            refererPathValues: $refererPathValues,
        );
    }

    /**
     * The secret-bearing path segment values of a URL that is not this request's
     * own. Null when the host cannot say, which means query-only scrubbing.
     *
     * @return array<int, string>|null
     */
    public function refererPathValues(string $url): ?array
    {
        if (! is_callable($this->refererPathValues)) {
            return null;
        }

        return ($this->refererPathValues)($url);
    }

    /**
     * The request headers a `$_SERVER` array carries, as `header-name => value`.
     *
     * Null rather than an empty array when there are none: `json_encode([])` is
     * `[]`, a JSON array, and the field is typed as an object on the wire, so an
     * empty result must travel as the null the contract already allows.
     *
     * @param  array<array-key, mixed>  $server
     * @return array<string, string>|null
     */
    private static function headers(array $server): ?array
    {
        $headers = [];

        foreach ($server as $key => $value) {
            if (! is_string($key)) {
                continue;
            }

            if (str_starts_with($key, 'HTTP_')) {
                $name = mb_strtolower(str_replace('_', '-', mb_substr($key, 5)));
            } elseif ($key === 'CONTENT_TYPE' || $key === 'CONTENT_LENGTH') {
                $name = mb_strtolower(str_replace('_', '-', $key));
            } else {
                continue;
            }

            if ($name === '' || ! is_scalar($value)) {
                continue;
            }

            $headers[$name] = (string) $value;
        }

        return $headers === [] ? null : $headers;
    }

    /**
     * The full URL of the request being handled, unscrubbed, or null when the
     * server array describes no request at all.
     *
     * @param  array<array-key, mixed>  $server
     */
    private static function url(array $server): ?string
    {
        $host = self::serverString($server, 'HTTP_HOST') ?? self::serverString($server, 'SERVER_NAME') ?? '';
        $uri = self::serverString($server, 'REQUEST_URI') ?? '';

        $url = $host === '' ? $uri : self::scheme($server).'://'.$host.$uri;

        return $url === '' ? null : $url;
    }

    /**
     * `HTTPS` is the only signal trusted here. `X-Forwarded-Proto` is a
     * client-settable header, and this SDK has no trusted-proxy configuration to
     * judge it by, so a host behind a TLS-terminating proxy sets `HTTPS` (every
     * mainstream setup already does) rather than having the SDK guess.
     *
     * @param  array<array-key, mixed>  $server
     */
    private static function scheme(array $server): string
    {
        $https = self::serverString($server, 'HTTPS');

        if ($https === null || $https === '' || mb_strtolower($https) === 'off') {
            return 'http';
        }

        return 'https';
    }

    /**
     * @param  array<array-key, mixed>  $server
     * @return array<int, string>
     */
    private static function argv(array $server): array
    {
        $argv = $server['argv'] ?? null;

        if (! is_array($argv)) {
            return [];
        }

        $arguments = [];

        foreach ($argv as $argument) {
            if (is_scalar($argument)) {
                $arguments[] = (string) $argument;
            }
        }

        return $arguments;
    }

    /**
     * One request-context value as a string, or null when it is absent or not
     * scalar. An empty string is returned as one, deliberately: it is what a
     * host set, and the `HTTP_HOST` fallback chain in {@see url()} treats "set
     * to empty" as an answer rather than falling through to `SERVER_NAME`.
     *
     * @param  array<array-key, mixed>  $server
     */
    private static function serverString(array $server, string $key): ?string
    {
        $value = $server[$key] ?? null;

        return is_scalar($value) ? (string) $value : null;
    }
}
