<?php

declare(strict_types=1);

namespace Ranetrace\Php\Errors;

use DateTimeImmutable;
use InvalidArgumentException;
use Ranetrace\Php\Config;
use Ranetrace\Php\Support\DataSanitizer;
use Ranetrace\Php\Support\Diagnostics;
use Ranetrace\Php\Support\ItemByteBudget;
use Ranetrace\Php\Support\Scrubber;
use Ranetrace\Php\Support\UserId;
use Ranetrace\Php\Support\Utf8;
use ReflectionMethod;
use Throwable;

/**
 * Shapes a throwable into the error item the Ranetrace API accepts.
 *
 * This is the ONE builder: `ranetrace/ranetrace-laravel` shapes its error items
 * here too, handing over what only a framework can answer through
 * {@see ErrorContext} rather than keeping a second copy of the caps. Every cap,
 * every truncation rule and the header allowlist are part of the wire contract:
 * the backend does strict field-set matching, so an item with an extra key, a
 * missing key or a wrong type is refused and counted as failed, never sent
 * again, and a builder that gets it wrong loses every error it builds.
 *
 * What a host is told to answer, it answers through {@see Config}: `environment`,
 * `project_root`, `framework`, `framework_version` and `user_resolver`. What it
 * observes per capture, it answers through {@see ErrorContext}. Nothing here
 * reaches for a superglobal or a framework.
 *
 * The item is 23 keys, all always present. The framework identity is a pair,
 * `framework` and `framework_version`, both nullable, which replaced the
 * `laravel_version` the Laravel SDK once sent and which is retired.
 *
 * `frames` is the trace as structured frames, `previous` the chain of previous
 * exceptions, nearest first. A frame never carries `args`: the trace's `args`
 * key is not read at all, because with `zend.exception_ignore_args` off a
 * frame's arguments are live values, objects holding credentials among them.
 * What a frame does carry is a few scrubbed source lines when it is in the
 * application's own code, so source lines leave the host by default; the
 * `errors.capture_source` switch turns every source line off, the item's
 * `context` included. {@see FrameCap} decides which frames a long trace keeps,
 * {@see SourceReader} reads every line, and {@see ErrorItemShedder} sheds
 * sources and frames first when the item is over the byte budget.
 *
 * `exception_context` is read from the throwable itself, not from
 * {@see ErrorContext}: it is what the throwable's own `context()` method
 * returns, the array Laravel's log reporter merges into a log entry, so it
 * travels with the throwable and needs no adapter code in either SDK.
 *
 * Every string taken from the throwable or the host passes through
 * {@see Utf8::repair()} before it is scrubbed or capped, so an invalid byte
 * becomes U+FFFD inside the cap rather than failing the JSON encode of its item.
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

    /**
     * A frame's `class` and `function`, and a previous exception's `type`, as
     * the backend bounds them.
     */
    private const int MAX_CODE_NAME_LENGTH = 1_000;

    private const int MAX_TYPE_LENGTH = 255;

    /**
     * How many previous exceptions the item carries, nearest first.
     */
    private const int MAX_PREVIOUS = 5;

    private const int MAX_HEADER_COUNT = 50;

    private const int MAX_HEADER_VALUE_LENGTH = 500;

    private const int MAX_CONSOLE_ARGV_COUNT = 50;

    private const int MAX_CONSOLE_ARGV_LENGTH = 500;

    /**
     * Bounds on `exception_context`. The backend allows 100 top-level keys, 5
     * levels of nesting and 16,384 bytes JSON-encoded, and a context past any
     * of them refuses its item. The SDK keeps half of each as headroom: a
     * context is host data that can grow without the host noticing, and
     * trimming it here costs part of one context where crossing the backend's
     * line costs the whole error report.
     *
     * The byte cap equals {@see ItemByteBudget::MAX_ITEM_FIELD_BYTES}, so a
     * context that fits here is never replaced wholesale by that budget.
     * String values are held to the header value cap, so one long value cannot
     * crowd out every key after it.
     */
    private const int MAX_EXCEPTION_CONTEXT_KEYS = 50;

    private const int MAX_EXCEPTION_CONTEXT_DEPTH = 3;

    private const int MAX_EXCEPTION_CONTEXT_STRING_LENGTH = 500;

    private const int MAX_EXCEPTION_CONTEXT_BYTES = 8_192;

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

    /**
     * @var list<FrameMapper>
     */
    private readonly array $frameMappers;

    /**
     * Set per build, so a mapper that fails on every frame writes one
     * diagnostics line per item rather than one per frame.
     */
    private bool $frameMapperFailureLogged = false;

    /**
     * @param  list<FrameMapper>  $frameMappers  Tried in order for every frame and previous throw site; the first non-null answer wins.
     *
     * @throws InvalidArgumentException When an entry is not a {@see FrameMapper}: a wiring mistake the developer can still fix.
     */
    public function __construct(
        private readonly Config $config,
        private readonly Scrubber $scrubber,
        private readonly Diagnostics $log,
        array $frameMappers = [],
    ) {
        foreach ($frameMappers as $mapper) {
            if (! $mapper instanceof FrameMapper) {
                throw new InvalidArgumentException('Every frame mapper must implement '.FrameMapper::class.', got '.get_debug_type($mapper).'.');
            }
        }

        $this->frameMappers = array_values($frameMappers);
    }

    /**
     * Build the 23-key error item.
     *
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
     *     exception_context: array<array-key, mixed>|null,
     *     frames: list<array<string, mixed>>|null,
     *     frames_omitted: int|null,
     *     previous: list<array<string, mixed>>|null,
     * }
     */
    public function build(Throwable $throwable, ErrorContext $context): array
    {
        $this->frameMapperFailureLogged = false;
        $captureSource = $this->config->get('errors.capture_source') === true;
        $reader = new SourceReader($this->scrubber, $this->log);

        // The item's own throw site is NOT passed through the frame mappers:
        // its `file` and `line` decide grouping, so mapping them is a separate
        // decision. To map it, wrap this location in $this->mapped(...).
        $throwSite = new FrameLocation($throwable->getFile(), $throwable->getLine());
        $file = $throwSite->file;
        $line = $throwSite->line;
        $isConsole = $context->isConsole;

        // Every location is announced to the reader before any is read, so
        // each file is read once however many frames share it.
        [$frames, $framesOmitted] = $this->draftFrames($throwable->getTrace(), $reader, $captureSource);
        $previous = $this->draftPreviousChain($throwable, $reader, $captureSource);

        if ($captureSource && $file !== '') {
            $reader->want($file, $line);
        }

        [$source, $highlightLine] = $captureSource ? $this->sourceContext($reader, $file, $line) : [null, null];

        // The message and the trace are secret-scrubbed BEFORE truncation, so a
        // secret cannot survive by being split across the length boundary. An
        // exception message can embed key=value secrets (PDO connection
        // strings, "invalid api_key=…"), and getTraceAsString() can carry them
        // in argument values.
        return [
            'message' => $this->truncate($this->scrubber->scrubString(Utf8::repair($throwable->getMessage())), self::MAX_MESSAGE_LENGTH),
            'file' => $this->boundFilePath($file),
            'line' => $line,
            'type' => Utf8::repair($throwable::class),
            'environment' => $this->stringConfig('environment'),
            'trace' => $this->truncate($this->scrubber->scrubString(Utf8::repair($throwable->getTraceAsString())), self::MAX_TRACE_LENGTH),
            'headers' => $isConsole ? null : $this->headers($context),
            'context' => $source,
            'highlight_line' => $highlightLine,
            'user' => $this->user(),
            'timestamp' => Utf8::repairNullable($context->timestamp) ?? (new DateTimeImmutable)->format('c'),
            'url' => $isConsole ? null : $this->url($context),
            'method' => $isConsole ? null : $this->method($context),
            'php_version' => (string) phpversion(),
            'framework' => $this->nullableStringConfig('framework'),
            'framework_version' => $this->nullableStringConfig('framework_version'),
            'is_console' => $isConsole,
            'console_command' => $isConsole ? $this->consoleCommand($context) : null,
            'console_arguments' => $isConsole ? $this->consoleArguments($context) : null,
            'exception_context' => $this->exceptionContext($throwable, $context),
            'frames' => $this->resolveFrameSources($frames, $reader),
            'frames_omitted' => $framesOmitted,
            'previous' => $previous === null ? null : array_map(
                fn (array $entry): array => $this->resolvePreviousSources($entry, $reader),
                $previous,
            ),
        ];
    }

    /**
     * The kept frames of a trace, as draft frames whose `source` is still the
     * location to read, together with how many middle frames were dropped.
     *
     * Only the keys a frame needs are read from each trace frame. `args` is
     * never touched.
     *
     * @param  array<int, array<string, mixed>>  $trace
     * @return array{0: list<array<string, mixed>>, 1: int}
     */
    private function draftFrames(array $trace, SourceReader $reader, bool $captureSource): array
    {
        $trace = array_values($trace);
        $positions = FrameCap::positions(count($trace), FrameCap::MAX_FRAMES);
        $frames = [];

        foreach ($positions as $position) {
            $raw = $trace[$position];

            $file = isset($raw['file']) && is_string($raw['file']) && $raw['file'] !== '' ? $raw['file'] : null;
            $line = isset($raw['line']) && is_int($raw['line']) ? $raw['line'] : null;
            $location = null;

            if ($file !== null && $line !== null) {
                $location = $this->mapped(new FrameLocation($file, $line));
                $file = $location->file;
                $line = $location->line;
            }

            $isVendor = $file !== null && $this->isVendor($file);
            $wantsSource = $captureSource && ! $isVendor && $location !== null && $line >= 1;

            if ($wantsSource) {
                $reader->want($location->file, $location->line);
            }

            $type = $raw['type'] ?? null;

            $frames[] = [
                'index' => $position,
                'file' => $file === null ? null : $this->boundFilePath($file),
                'line' => $line === null ? null : max(0, $line),
                'class' => $this->codeName($raw['class'] ?? null, self::MAX_CODE_NAME_LENGTH),
                'function' => $this->codeName($raw['function'] ?? null, self::MAX_CODE_NAME_LENGTH),
                'type' => $type === '->' || $type === '::' ? $type : null,
                'is_vendor' => $isVendor,
                'source' => $wantsSource ? $location : null,
            ];
        }

        return [$frames, count($trace) - count($frames)];
    }

    /**
     * The previous exceptions, nearest first, at most {@see MAX_PREVIOUS}, as
     * drafts; null when there are none.
     *
     * A chain that loops back on itself (only reflection can build one) stops
     * at the first exception already seen. Anything failing while the chain is
     * read costs the chain, never the error report.
     *
     * @return list<array<string, mixed>>|null
     */
    private function draftPreviousChain(Throwable $throwable, SourceReader $reader, bool $captureSource): ?array
    {
        $chain = [];
        $seen = [spl_object_id($throwable) => true];

        try {
            $current = $throwable->getPrevious();

            while ($current !== null && count($chain) < self::MAX_PREVIOUS && ! isset($seen[spl_object_id($current)])) {
                $seen[spl_object_id($current)] = true;
                $chain[] = $this->draftPrevious($current, $reader, $captureSource);
                $current = $current->getPrevious();
            }
        } catch (Throwable $failure) {
            $this->log->warning('Ranetrace could not read the previous exception chain', [
                'exception' => $failure->getMessage(),
            ]);

            return null;
        }

        return $chain === [] ? null : $chain;
    }

    /**
     * One previous exception, with its own throw site and its own frames. Its
     * throw site always gets a source, vendor or not, like the item's
     * `context`.
     *
     * @return array<string, mixed>
     */
    private function draftPrevious(Throwable $previous, SourceReader $reader, bool $captureSource): array
    {
        $location = new FrameLocation($previous->getFile(), $previous->getLine());

        if ($location->file !== '') {
            $location = $this->mapped($location);
        }

        $wantsSource = $captureSource && $location->file !== '' && $location->line >= 1;

        if ($wantsSource) {
            $reader->want($location->file, $location->line);
        }

        [$frames, $framesOmitted] = $this->draftFrames($previous->getTrace(), $reader, $captureSource);

        return [
            'type' => (string) $this->codeName($previous::class, self::MAX_TYPE_LENGTH),
            'message' => $this->truncate($this->scrubber->scrubString(Utf8::repair($previous->getMessage())), self::MAX_MESSAGE_LENGTH),
            'file' => $this->boundFilePath($location->file),
            'line' => max(0, $location->line),
            'source' => $wantsSource ? $location : null,
            'frames' => $frames,
            'frames_omitted' => $framesOmitted,
        ];
    }

    /**
     * Swap each draft frame's location for the source object read there.
     *
     * @param  list<array<string, mixed>>  $frames
     * @return list<array<string, mixed>>
     */
    private function resolveFrameSources(array $frames, SourceReader $reader): array
    {
        foreach ($frames as $position => $frame) {
            $frames[$position]['source'] = $this->sourceObject($frame['source'], $reader);
        }

        return $frames;
    }

    /**
     * @param  array<string, mixed>  $entry
     * @return array<string, mixed>
     */
    private function resolvePreviousSources(array $entry, SourceReader $reader): array
    {
        $entry['source'] = $this->sourceObject($entry['source'], $reader);
        $entry['frames'] = $this->resolveFrameSources($entry['frames'], $reader);

        return $entry;
    }

    /**
     * @return array{start_line: int, lines: list<string>}|null
     */
    private function sourceObject(mixed $location, SourceReader $reader): ?array
    {
        if (! $location instanceof FrameLocation) {
            return null;
        }

        return $reader->window($location->file, $location->line)?->sourceObject($location->line);
    }

    /**
     * The location the first frame mapper answers for, or the location itself
     * when none does. A mapper that throws, or answers with no file or a line
     * before 1, is passed over.
     */
    private function mapped(FrameLocation $location): FrameLocation
    {
        foreach ($this->frameMappers as $mapper) {
            try {
                $mapped = $mapper->map($location);
            } catch (Throwable $failure) {
                if (! $this->frameMapperFailureLogged) {
                    $this->frameMapperFailureLogged = true;
                    $this->log->warning('Ranetrace frame mapper failed', [
                        'mapper' => $mapper::class,
                        'exception' => $failure->getMessage(),
                    ]);
                }

                continue;
            }

            if ($mapped !== null && $mapped->file !== '' && $mapped->line >= 1) {
                return $mapped;
            }
        }

        return $location;
    }

    /**
     * Whether an absolute path is under the project's vendor directory,
     * `{project_root}/vendor`, with either separator on either side.
     *
     * The vendor directory is not configurable: Composer's own `vendor-dir`
     * setting is rarely changed, and a host that changes it gets its vendor
     * frames counted as its own, which costs extra source lines, never a
     * report.
     */
    private function isVendor(string $file): bool
    {
        $root = $this->config->get('project_root');
        $root = is_scalar($root) ? mb_rtrim(str_replace('\\', '/', (string) $root), '/') : '';

        if ($root === '') {
            return false;
        }

        return str_starts_with(str_replace('\\', '/', $file), $root.'/vendor/');
    }

    /**
     * A class or function name as a frame carries it, with the absolute paths
     * PHP embeds in some names made relative to the project root: a closure is
     * named `{closure:/abs/app/file.php:12}` and an anonymous class
     * `class@anonymous` + NUL + `/abs/app/file.php:12$0`. The NUL becomes a
     * space, so the name still reads as the class and where it is declared.
     */
    private function codeName(mixed $name, int $maxLength): ?string
    {
        if (! is_string($name) || $name === '') {
            return null;
        }

        $name = str_replace("\0", ' ', $name);

        // Compared against the raw name, like boundFilePath(), and only at the
        // start of a path: after the start of the name, a space, `:`, `{` or `(`.
        $root = $this->config->get('project_root');
        $root = is_scalar($root) ? mb_rtrim((string) $root, '/\\') : '';

        if ($root !== '') {
            $name = preg_replace('~(?<=^|[\s:{(])'.preg_quote($root, '~').'[/\\\\]~', '', $name) ?? $name;
        }

        return $this->truncate(Utf8::repair($name), $maxLength);
    }

    /**
     * What the throwable's own public `context()` method returns, flattened,
     * scrubbed and bounded, or null when it has none to give.
     *
     * The method is host code called from inside the capture path, so a
     * `context()` that throws costs the context and nothing else. URL values
     * are scrubbed with the per-URL resolver the Referer uses, because a
     * context holds URLs from requests other than this one.
     *
     * @return array<array-key, mixed>|null
     */
    private function exceptionContext(Throwable $throwable, ErrorContext $context): ?array
    {
        if (! method_exists($throwable, 'context') || ! (new ReflectionMethod($throwable, 'context'))->isPublic()) {
            return null;
        }

        try {
            $raw = $throwable->context();

            if (! is_array($raw) || $raw === []) {
                return null;
            }

            $scrubbed = $this->scrubber->scrubDeep(
                Utf8::repairDeep(DataSanitizer::sanitizeForSerialization($raw)),
                $context->refererPathValues(...),
            );
        } catch (Throwable $failure) {
            $this->log->warning('Ranetrace could not read the exception context', [
                'exception' => $failure->getMessage(),
            ]);

            return null;
        }

        if (! is_array($scrubbed) || $scrubbed === []) {
            return null;
        }

        return $this->fitExceptionContext($this->boundExceptionContextLevel(
            array_slice($scrubbed, 0, self::MAX_EXCEPTION_CONTEXT_KEYS, true),
            1,
        ));
    }

    /**
     * Cut every array nested past the depth cap down to the depth marker, and
     * every string value down to the string cap. `$level` is the nesting level
     * of `$values` itself, counted the way the backend does: a flat array is
     * level 1.
     *
     * @param  array<array-key, mixed>  $values
     * @return array<array-key, mixed>
     */
    private function boundExceptionContextLevel(array $values, int $level): array
    {
        foreach ($values as $key => $value) {
            if (is_array($value)) {
                $values[$key] = $level >= self::MAX_EXCEPTION_CONTEXT_DEPTH
                    ? DataSanitizer::MAX_DEPTH_MARKER
                    : $this->boundExceptionContextLevel($value, $level + 1);

                continue;
            }

            if (is_string($value)) {
                $values[$key] = $this->truncate($value, self::MAX_EXCEPTION_CONTEXT_STRING_LENGTH);
            }
        }

        return $values;
    }

    /**
     * Drop trailing top-level keys until the context fits the byte cap, null
     * when not even its first key does.
     *
     * A context JSON cannot encode at all is null too: sent as it is, it would
     * fail to encode the whole batch. Nothing known gets this far, since
     * {@see exceptionContext()} repairs invalid UTF-8 and
     * {@see DataSanitizer::sanitizeForSerialization()} spells INF and NAN as
     * strings, so this is a backstop for whatever else JSON may refuse.
     *
     * @param  array<array-key, mixed>  $bounded
     * @return array<array-key, mixed>|null
     */
    private function fitExceptionContext(array $bounded): ?array
    {
        while ($bounded !== []) {
            $encoded = json_encode($bounded);

            if ($encoded === false) {
                return null;
            }

            if (mb_strlen($encoded, '8bit') <= self::MAX_EXCEPTION_CONTEXT_BYTES) {
                return $bounded;
            }

            array_pop($bounded);
        }

        return null;
    }

    /**
     * The item's `context` and `highlight_line`: the failing line plus five
     * lines either side as one string, and the 1-indexed position of the
     * failing line within it. Both null when the file cannot be read.
     *
     * @return array{0: string|null, 1: int|null}
     */
    private function sourceContext(SourceReader $reader, string $file, int $line): array
    {
        if ($file === '') {
            return [null, null];
        }

        $window = $reader->window($file, $line);

        return $window === null ? [null, null] : [$window->context, $window->highlightLine($line)];
    }

    /**
     * Ship a path relative to the project root rather than the absolute server
     * path, which would leak the deployment layout. A path outside the project
     * root (a PHP built-in, an eval'd file) is kept absolute but LEFT-truncated:
     * when a path is too long it is the tail, not the head, that says which file
     * this is.
     *
     * The root is stripped only at a directory boundary, so a root of `/app`
     * leaves `/application/x.php` alone, and a trailing separator on the root
     * makes no difference. A path equal to the root names no file inside it
     * and is kept as it is.
     */
    private function boundFilePath(string $file): string
    {
        if ($file === '') {
            return $file;
        }

        // Compared byte for byte against the raw path, so the root is read
        // unrepaired: a repaired copy would no longer prefix a raw path that
        // shares its invalid bytes.
        $root = $this->config->get('project_root');
        $root = is_scalar($root) ? (string) $root : '';

        if ($root !== '') {
            $root = mb_rtrim($root, '/\\');

            // The separator after the root is ASCII, so the root ends on a
            // whole character in the path and the character offset below
            // matches the byte prefix compared here.
            if (str_starts_with($file, $root.'/') || str_starts_with($file, $root.'\\')) {
                $file = mb_ltrim(mb_substr($file, mb_strlen($root)), '/\\');
            }
        }

        $file = Utf8::repair($file);

        if (mb_strlen($file) > self::MAX_FILE_PATH_LENGTH) {
            $file = mb_substr($file, -self::MAX_FILE_PATH_LENGTH);
        }

        return $file;
    }

    /**
     * The request headers, as `header-name => [values]`, masked and bounded.
     *
     * Null when the host observed none: `json_encode([])` is `[]`, a JSON array,
     * and the field is typed as an object on the wire, so an empty result must
     * travel as the null the contract already allows.
     *
     * @return array<string, array<int, string>>|null
     */
    private function headers(ErrorContext $context): ?array
    {
        $headers = $context->headers;

        if ($headers === null || $headers === []) {
            return null;
        }

        $bounded = [];

        foreach (array_slice($headers, 0, self::MAX_HEADER_COUNT, true) as $name => $values) {
            $name = is_string($name) ? Utf8::repair($name) : $name;

            if (! in_array($name, self::SAFE_HEADERS, true)) {
                $bounded[$name] = ['***'];

                continue;
            }

            // A header bag can hold a null value, so every value is cast the
            // way `(string) $value` always did rather than type-hinted away.
            $bounded[$name] = array_map(
                fn (mixed $value): string => $this->boundHeaderValue($name, is_scalar($value) ? Utf8::repair((string) $value) : '', $context),
                is_array($values) ? array_values($values) : [$values],
            );
        }

        return $bounded;
    }

    /**
     * Scrub the Referer (it can carry reset tokens and signed-URL signatures in
     * its query string AND in its path) and truncate to the per-value cap.
     */
    private function boundHeaderValue(string $name, string $value, ErrorContext $context): string
    {
        if ($name === 'referer') {
            $value = (string) $this->scrubber->scrubUrlPath(
                $this->scrubber->scrubUrl($value),
                $context->refererPathValues($value),
            );
        }

        return $this->truncate($value, self::MAX_HEADER_VALUE_LENGTH);
    }

    /**
     * The URL of the request being handled, with sensitive query parameters
     * redacted and, where the host could name them, its secret-bearing path
     * segments too.
     */
    private function url(ErrorContext $context): ?string
    {
        if ($context->url === null || $context->url === '') {
            return null;
        }

        return $this->truncate(
            (string) $this->scrubber->scrubUrlPath(
                $this->scrubber->scrubUrl(Utf8::repair($context->url)),
                $context->sensitivePathValues,
            ),
            self::MAX_URL_LENGTH,
        );
    }

    private function method(ErrorContext $context): ?string
    {
        $method = $context->method;

        return $method === null || $method === '' ? null : mb_strtoupper(Utf8::repair($method));
    }

    /**
     * The command line the process was started with, scrubbed for `--token=…`
     * style secrets.
     */
    private function consoleCommand(ErrorContext $context): ?string
    {
        $command = $context->consoleCommand;

        return $command === null ? null : $this->scrubber->scrubString(Utf8::repair($command));
    }

    /**
     * The same command line as an array, count- and length-bounded.
     *
     * @return array<int, string>|null
     */
    private function consoleArguments(ErrorContext $context): ?array
    {
        $arguments = $context->consoleArguments;

        if ($arguments === null) {
            return null;
        }

        $strings = [];

        foreach ($arguments as $argument) {
            if (is_scalar($argument)) {
                $strings[] = Utf8::repair((string) $argument);
            }
        }

        return array_map(
            fn (string $argument): string => $this->truncate(
                $this->scrubber->scrubString($argument),
                self::MAX_CONSOLE_ARGV_LENGTH,
            ),
            array_slice($strings, 0, self::MAX_CONSOLE_ARGV_COUNT)
        );
    }

    /**
     * The current user, as the host's resolver reports them.
     *
     * The email is PII, so it only travels when `errors.capture_user_email` is
     * on; the key is always present because the field set is strict. The
     * resolver is host code called from inside the capture path, so its failure
     * is contained here rather than costing the whole error report.
     *
     * The backend takes the id only as an int or a string of at most 255
     * characters and the email only as a string of at most 255 characters, and
     * an item of any other shape is refused whole, so a resolver that
     * reports anything else sends no user, or no email, instead.
     *
     * @return array{id: int|string, email: ?string}|null
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

        if (! is_array($resolved)) {
            return null;
        }

        $id = UserId::accepted($resolved['id'] ?? null);

        if ($id === null) {
            return null;
        }

        $email = $resolved['email'] ?? null;
        $email = is_string($email) ? Utf8::repair($email) : $email;

        return [
            'id' => $id,
            'email' => $this->config->get('errors.capture_user_email') === true
                && is_string($email)
                && mb_strlen($email) <= UserId::MAX_LENGTH
                    ? $email
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

    private function stringConfig(string $dotKey): string
    {
        $value = $this->config->get($dotKey);

        return is_scalar($value) ? Utf8::repair((string) $value) : '';
    }

    private function nullableStringConfig(string $dotKey): ?string
    {
        $value = $this->config->get($dotKey);

        return is_scalar($value) && (string) $value !== '' ? Utf8::repair((string) $value) : null;
    }
}
