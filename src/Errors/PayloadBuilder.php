<?php

declare(strict_types=1);

namespace Ranetrace\Php\Errors;

use DateTimeImmutable;
use Ranetrace\Php\Config;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;
use Throwable;

/**
 * Shapes a throwable into the error item the Ranetrace API accepts.
 *
 * Ported from `ranetrace/ranetrace-laravel` (`src/Ranetrace.php`,
 * `buildErrorPayload()` and its helpers). Every cap, every truncation rule and
 * the header allowlist are part of the wire contract and must not drift from
 * that SDK: the backend does strict field-set matching, so a payload with an
 * extra key, a missing key or a wrong type gets the WHOLE batch rejected with a
 * 422, dropping every item in it and pausing the feature for fifteen minutes.
 *
 * The one deliberate difference is the framework identity. The Laravel SDK
 * sends `laravel_version`; a framework-agnostic SDK cannot, so this builder
 * sends `framework` and `framework_version` instead, both always present and
 * both nullable, read from config because the SDK has no framework to ask. That
 * makes the item 19 keys rather than 18 and requires the backend validator to
 * accept the new shape first (lockstep with backend task #81).
 *
 * What the Laravel SDK discovers from its container, this one is told:
 * `app()->environment()` becomes the `environment` config value, `base_path()`
 * becomes `project_root`, `Auth::user()` becomes the `user_resolver` callable,
 * and the `Request` object becomes a plain `$_SERVER` array handed in by the
 * caller.
 */
final class PayloadBuilder
{
    /**
     * Appended to fields that exceed their length limit. Counted INSIDE the
     * limit: the final string, suffix included, is never longer than the cap.
     */
    public const string TRUNCATION_SUFFIX = '... (truncated)';

    /**
     * Per-field caps bound the size of a SINGLE error item. The batch as a
     * whole is kept under the API's 5MB request limit by the worker's
     * pre-flight byte-budget trim. NOT user-tunable: raising any of these
     * widens per-item size and the 413 risk.
     */
    private const int MAX_MESSAGE_LENGTH = 10_000;

    private const int MAX_TRACE_LENGTH = 5_000;

    private const int MAX_FILE_PATH_LENGTH = 500;

    private const int MAX_URL_LENGTH = 2_000;

    private const int MAX_SOURCE_FILE_BYTES = 1_048_576;

    private const int MAX_CONTEXT_LINE_LENGTH = 2_000;

    /**
     * The source preview is the failing line plus five lines either side.
     */
    private const int CONTEXT_LINES = 11;

    private const int CONTEXT_LINES_BEFORE = 5;

    private const int MAX_HEADER_COUNT = 50;

    private const int MAX_HEADER_VALUE_LENGTH = 500;

    private const int MAX_CONSOLE_ARGV_COUNT = 50;

    private const int MAX_CONSOLE_ARGV_LENGTH = 500;

    /**
     * Request headers considered safe to capture in plaintext. Every other
     * header is masked, so a header carrying a secret that we did not
     * anticipate is masked by default rather than leaked.
     *
     * `x-forwarded-for` is deliberately NOT listed: it carries the client IP
     * chain (PII), and the SDK's posture is that no IP leaves the host. It is
     * masked like any other non-allowlisted header.
     *
     * @var array<int, string>
     */
    private const array SAFE_HEADERS = [
        'accept',
        'accept-charset',
        'accept-encoding',
        'accept-language',
        'cache-control',
        'connection',
        'content-length',
        'content-type',
        'host',
        'referer',
        'user-agent',
        'x-requested-with',
        'x-forwarded-proto',
        'x-forwarded-host',
    ];

    public function __construct(
        private readonly Config $config,
        private readonly SecretScrubber $scrubber,
        private readonly InternalLogger $log,
    ) {}

    /**
     * Build the 19-key error item.
     *
     * `$isConsole` is passed in rather than read from `PHP_SAPI` here so the
     * caller owns the decision (and so both branches are reachable from a test
     * suite, which always runs under the CLI SAPI).
     *
     * @param  array<array-key, mixed>  $server  The `$_SERVER` array to read the request and argv from.
     * @return array{
     *     message: string,
     *     file: string,
     *     line: int,
     *     type: string,
     *     environment: string,
     *     trace: string,
     *     headers: array<string, array<int, string>>|null,
     *     context: string|null,
     *     highlight_line: int|null,
     *     user: array{id: mixed, email: mixed}|null,
     *     timestamp: string,
     *     url: string|null,
     *     method: string|null,
     *     php_version: string,
     *     framework: string|null,
     *     framework_version: string|null,
     *     is_console: bool,
     *     console_command: string|null,
     *     console_arguments: array<int, string>|null,
     * }
     */
    public function build(Throwable $throwable, array $server, bool $isConsole): array
    {
        $file = $throwable->getFile();
        $line = $throwable->getLine();

        [$context, $highlightLine] = $this->sourceContext($file, $line);

        // The message and the trace are secret-scrubbed BEFORE truncation, so a
        // secret cannot survive by being split across the length boundary. An
        // exception message can embed key=value secrets (PDO connection
        // strings, "invalid api_key=…"), and getTraceAsString() can carry them
        // in argument values.
        return [
            'message' => $this->truncate($this->scrubber->scrubString($throwable->getMessage()), self::MAX_MESSAGE_LENGTH),
            'file' => $this->boundFilePath($file),
            'line' => $line,
            'type' => $throwable::class,
            'environment' => $this->stringConfig('environment'),
            'trace' => $this->truncate($this->scrubber->scrubString($throwable->getTraceAsString()), self::MAX_TRACE_LENGTH),
            'headers' => $isConsole ? null : $this->headers($server),
            'context' => $context,
            'highlight_line' => $highlightLine,
            'user' => $this->user(),
            'timestamp' => (new DateTimeImmutable)->format('c'),
            'url' => $isConsole ? null : $this->url($server),
            'method' => $isConsole ? null : $this->method($server),
            'php_version' => (string) phpversion(),
            'framework' => $this->nullableStringConfig('framework'),
            'framework_version' => $this->nullableStringConfig('framework_version'),
            'is_console' => $isConsole,
            'console_command' => $isConsole ? $this->consoleCommand($server) : null,
            'console_arguments' => $isConsole ? $this->consoleArguments($server) : null,
        ];
    }

    /**
     * The failing line plus five lines either side, dedented, together with the
     * 1-indexed position of the failing line within that window.
     *
     * Only read files that are readable and reasonably sized: a generated or
     * concatenated multi-megabyte file would be read into memory in full for
     * eleven lines of preview.
     *
     * @return array{0: string|null, 1: int|null}
     */
    private function sourceContext(string $file, int $line): array
    {
        if ($file === '' || ! is_readable($file) || filesize($file) >= self::MAX_SOURCE_FILE_BYTES) {
            return [null, null];
        }

        $lines = file($file);

        if (! is_array($lines)) {
            return [null, null];
        }

        // Clamped at the start of the file, so an exception on line 3 shows
        // lines 1 to 11 and highlights the third of them.
        $startLine = max(0, $line - self::CONTEXT_LINES_BEFORE - 1);

        $window = array_map(
            fn (string $codeLine): string => $this->capContextLine($codeLine),
            array_slice($lines, $startLine, self::CONTEXT_LINES, true)
        );

        return [$this->dedent(implode('', $window)), $line - $startLine];
    }

    /**
     * Cap a single source line, preserving a trailing newline so the eleven-line
     * structure survives. Guards against a minified or generated line bloating
     * the item.
     *
     * The suffix is added OUTSIDE the cap here (unlike {@see truncate()}), which
     * is the Laravel SDK's behaviour: the context field has no field-level cap
     * of its own, so the overshoot of fifteen characters per line is harmless
     * and matching the sibling SDK byte for byte is worth more than internal
     * consistency.
     */
    private function capContextLine(string $line): string
    {
        $newline = str_ends_with($line, "\n") ? "\n" : '';
        $content = mb_rtrim($line, "\n");

        if (mb_strlen($content) > self::MAX_CONTEXT_LINE_LENGTH) {
            $content = mb_substr($content, 0, self::MAX_CONTEXT_LINE_LENGTH).self::TRUNCATION_SUFFIX;
        }

        return $content.$newline;
    }

    /**
     * Right-trim every line and strip the smallest indentation they share, so a
     * snippet from deep inside a nested method does not arrive as a column of
     * whitespace with code hiding off to the right.
     */
    private function dedent(string $code): string
    {
        $lines = array_map(mb_rtrim(...), explode("\n", $code));

        $minimumIndent = null;

        foreach ($lines as $line) {
            if (mb_trim($line) === '') {
                continue;
            }

            $indent = mb_strlen($line) - mb_strlen(mb_ltrim($line));

            if ($minimumIndent === null || $indent < $minimumIndent) {
                $minimumIndent = $indent;
            }
        }

        if ($minimumIndent === null || $minimumIndent === 0) {
            return implode("\n", $lines);
        }

        foreach ($lines as $index => $line) {
            if (mb_trim($line) !== '') {
                $lines[$index] = mb_substr($line, $minimumIndent);
            }
        }

        return implode("\n", $lines);
    }

    /**
     * Ship a path relative to the project root rather than the absolute server
     * path, which would leak the deployment layout. A path outside the project
     * root (a PHP built-in, an eval'd file) is kept absolute but LEFT-truncated:
     * when a path is too long it is the tail, not the head, that says which file
     * this is.
     */
    private function boundFilePath(string $file): string
    {
        if ($file === '') {
            return $file;
        }

        $root = $this->stringConfig('project_root');

        if ($root !== '' && str_starts_with($file, $root)) {
            $file = mb_ltrim(mb_substr($file, mb_strlen($root)), '/\\');
        }

        if (mb_strlen($file) > self::MAX_FILE_PATH_LENGTH) {
            $file = mb_substr($file, -self::MAX_FILE_PATH_LENGTH);
        }

        return $file;
    }

    /**
     * The request headers, as `header-name => [values]`.
     *
     * Returns null rather than an empty array when the server array carries no
     * headers at all: `json_encode([])` is `[]`, a JSON array, and the field is
     * typed as an object on the wire, so an empty result must travel as the
     * null the contract already allows.
     *
     * @param  array<array-key, mixed>  $server
     * @return array<string, array<int, string>>|null
     */
    private function headers(array $server): ?array
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

        if ($headers === []) {
            return null;
        }

        return $this->maskAndBoundHeaders($headers);
    }

    /**
     * Mask every header not on {@see SAFE_HEADERS} and cap both the header
     * count and the per-value length.
     *
     * @param  array<string, string>  $headers
     * @return array<string, array<int, string>>
     */
    private function maskAndBoundHeaders(array $headers): array
    {
        $bounded = [];

        foreach (array_slice($headers, 0, self::MAX_HEADER_COUNT, true) as $name => $value) {
            $bounded[$name] = in_array($name, self::SAFE_HEADERS, true)
                ? [$this->boundHeaderValue($name, $value)]
                : ['***'];
        }

        return $bounded;
    }

    /**
     * Scrub the Referer (it can carry reset tokens and signed-URL signatures in
     * its query string) and truncate to the per-value cap.
     */
    private function boundHeaderValue(string $name, string $value): string
    {
        if ($name === 'referer') {
            $value = (string) $this->scrubber->scrubUrl($value);
        }

        return $this->truncate($value, self::MAX_HEADER_VALUE_LENGTH);
    }

    /**
     * The full URL of the request being handled, with sensitive query
     * parameters redacted.
     *
     * Only the QUERY string is scrubbed. The Laravel SDK also redacts path
     * segments a route names `{token}` or `{hash}`, using the matched route as
     * the oracle for which segments are secret; this SDK has no router to ask,
     * so a host that knows better scrubs the path itself before handing over a
     * server array.
     *
     * @param  array<array-key, mixed>  $server
     */
    private function url(array $server): ?string
    {
        $host = $this->serverString($server, 'HTTP_HOST') ?? $this->serverString($server, 'SERVER_NAME') ?? '';
        $uri = $this->serverString($server, 'REQUEST_URI') ?? '';

        $url = $host === '' ? $uri : $this->scheme($server).'://'.$host.$uri;

        if ($url === '') {
            return null;
        }

        return $this->truncate((string) $this->scrubber->scrubUrl($url), self::MAX_URL_LENGTH);
    }

    /**
     * `HTTPS` is the only signal trusted here. `X-Forwarded-Proto` is a client
     * -settable header, and the SDK has no trusted-proxy configuration to judge
     * it by, so a host behind a TLS-terminating proxy sets `HTTPS` (every
     * mainstream setup already does) rather than having the SDK guess.
     *
     * @param  array<array-key, mixed>  $server
     */
    private function scheme(array $server): string
    {
        $https = $this->serverString($server, 'HTTPS');

        if ($https === null || $https === '' || mb_strtolower($https) === 'off') {
            return 'http';
        }

        return 'https';
    }

    /**
     * @param  array<array-key, mixed>  $server
     */
    private function method(array $server): ?string
    {
        $method = $this->serverString($server, 'REQUEST_METHOD');

        return $method === null || $method === '' ? null : mb_strtoupper($method);
    }

    /**
     * The command line the process was started with, scrubbed for `--token=…`
     * style secrets.
     *
     * @param  array<array-key, mixed>  $server
     */
    private function consoleCommand(array $server): ?string
    {
        $argv = $this->argv($server);

        if ($argv === []) {
            return null;
        }

        return $this->scrubber->scrubString(implode(' ', $argv));
    }

    /**
     * The same command line as an array, count- and length-bounded.
     *
     * @param  array<array-key, mixed>  $server
     * @return array<int, string>
     */
    private function consoleArguments(array $server): array
    {
        return array_map(
            fn (string $argument): string => $this->truncate(
                $this->scrubber->scrubString($argument),
                self::MAX_CONSOLE_ARGV_LENGTH,
            ),
            array_slice($this->argv($server), 0, self::MAX_CONSOLE_ARGV_COUNT)
        );
    }

    /**
     * @param  array<array-key, mixed>  $server
     * @return array<int, string>
     */
    private function argv(array $server): array
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
     * The current user, as the host's resolver reports them.
     *
     * The email is PII, so it only travels when `errors.capture_user_email` is
     * on; the key is always present because the field set is strict. The
     * resolver is host code called from inside the capture path, so its failure
     * is contained here rather than costing the whole error report.
     *
     * @return array{id: mixed, email: mixed}|null
     */
    private function user(): ?array
    {
        $resolver = $this->config->get('user_resolver');

        if (! is_callable($resolver)) {
            return null;
        }

        try {
            $resolved = $resolver();
        } catch (Throwable $failure) {
            $this->log->warning('Ranetrace user resolver failed', [
                'exception' => $failure->getMessage(),
            ]);

            return null;
        }

        if (! is_array($resolved) || ! array_key_exists('id', $resolved) || $resolved['id'] === null) {
            return null;
        }

        return [
            'id' => $resolved['id'],
            'email' => $this->config->get('errors.capture_user_email') === true
                ? ($resolved['email'] ?? null)
                : null,
        ];
    }

    /**
     * Truncate to at most $maxLength characters, the suffix included, so the
     * final string never exceeds the cap.
     */
    private function truncate(string $value, int $maxLength): string
    {
        if (mb_strlen($value) <= $maxLength) {
            return $value;
        }

        return mb_substr($value, 0, $maxLength - mb_strlen(self::TRUNCATION_SUFFIX)).self::TRUNCATION_SUFFIX;
    }

    /**
     * @param  array<array-key, mixed>  $server
     */
    private function serverString(array $server, string $key): ?string
    {
        $value = $server[$key] ?? null;

        return is_scalar($value) ? (string) $value : null;
    }

    private function stringConfig(string $dotKey): string
    {
        $value = $this->config->get($dotKey);

        return is_scalar($value) ? (string) $value : '';
    }

    private function nullableStringConfig(string $dotKey): ?string
    {
        $value = $this->config->get($dotKey);

        return is_scalar($value) && (string) $value !== '' ? (string) $value : null;
    }
}
