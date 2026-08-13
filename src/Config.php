<?php

declare(strict_types=1);

namespace Ranetrace\Php;

use Composer\Autoload\ClassLoader;
use InvalidArgumentException;
use ReflectionClass;

/**
 * Resolved SDK configuration: an array literal layered over `RANETRACE_*`
 * environment fallbacks, layered over the built-in defaults.
 *
 * The key set mirrors `ranetrace/ranetrace-laravel`'s `config/ranetrace.php`
 * (same names, same defaults) minus the queue keys, which are Laravel-only:
 * this SDK writes straight to the file buffer. It adds the keys a
 * framework-agnostic runtime has to be told rather than discover: `base_url`,
 * `environment`, `project_root`, `buffer_path`, `framework`,
 * `framework_version`, `user_resolver`, `flush_on_shutdown` and
 * `javascript_errors.allowed_origins`.
 *
 * Two failure postures live side by side here on purpose. A misconfiguration is
 * a programming error the developer can still fix, so the constructor throws
 * loudly on one. A capture failure at runtime is never worth breaking the host
 * application over, so every capture path swallows instead. Unknown keys are
 * kept untouched rather than rejected, so a host app written against a newer
 * SDK config surface still boots on an older SDK.
 */
final class Config
{
    /**
     * Browser noise that is never worth an error record. Ported verbatim from
     * `ranetrace-laravel`; the JS capture script and the relay both filter on
     * it, so the two lists must stay identical.
     *
     * @var array<int, string>
     */
    public const array DEFAULT_IGNORED_JAVASCRIPT_ERRORS = [
        // Browser quirks and unfixable issues.
        'ResizeObserver loop limit exceeded',
        'ResizeObserver loop completed with undelivered notifications',

        // Cross-origin errors (no useful information due to CORS).
        'Script error.',
        'Script error',

        // Network errors (usually user connection issues, not bugs).
        'Failed to fetch',
        'NetworkError when attempting to fetch resource',
        'Network request failed',
        'Load failed',

        // Bundler chunk loading (usually navigation or stale deployments).
        'Loading chunk',
        'ChunkLoadError',

        // User-cancelled operations.
        'cancelled',
        'canceled',
        'The operation was aborted',
        'AbortError',

        // Browser extension interference.
        'Illegal invocation',
    ];

    public const string DEFAULT_BASE_URL = 'https://api.ranetrace.com/v1';

    /**
     * Every value the SDK reads, keyed by dot path.
     *
     * @var array<string, mixed>
     */
    private array $values;

    /**
     * @param  array<string, mixed>  $config  Nested config array; anything absent falls back to env, then to the default.
     *
     * @throws InvalidArgumentException When `key` is not a string or `user_resolver` is not callable.
     */
    public function __construct(array $config = [])
    {
        $this->values = $config;

        foreach (self::schema() as $dotKey => $definition) {
            if (self::hasDot($this->values, $dotKey)) {
                self::setDot($this->values, $dotKey, self::coerce(
                    self::getDot($this->values, $dotKey),
                    $definition['type'],
                    $dotKey,
                ));

                continue;
            }

            $raw = $definition['env'] !== null ? self::readEnv($definition['env']) : null;

            self::setDot(
                $this->values,
                $dotKey,
                $raw === null ? $definition['default'] : self::coerce($raw, $definition['type'], $dotKey),
            );
        }
    }

    /**
     * Read a value by dot path, e.g. `logging.level` or `batch.lock_wait`.
     */
    public function get(string $dotKey, mixed $default = null): mixed
    {
        if (! self::hasDot($this->values, $dotKey)) {
            return $default;
        }

        return self::getDot($this->values, $dotKey);
    }

    /**
     * Whether capture is on: the master switch, the feature's own switch, and a
     * non-empty API key must all agree. Passing no feature answers the master
     * switch and the key alone.
     */
    public function enabled(?string $feature = null): bool
    {
        if ($this->get('enabled') !== true) {
            return false;
        }

        if ($this->key() === '') {
            return false;
        }

        if ($feature === null) {
            return true;
        }

        return $this->get($feature.'.enabled') === true;
    }

    public function key(): string
    {
        $key = $this->get('key');

        return is_string($key) ? $key : '';
    }

    /**
     * The directory every on-disk artefact of the SDK lives in: the spool files
     * and their locks, the pause store, the worker state and the internal log.
     *
     * The schema default cannot carry this on its own. It only applies when the
     * key is absent, and a host that passes `buffer_path` explicitly as null or
     * an empty string gets that value back untouched, so the fallback is
     * repeated here. The trailing slash is trimmed because every caller appends
     * `/name`, and a configured `/var/spool/` would otherwise produce `//`.
     */
    public function bufferPath(): string
    {
        $path = $this->get('buffer_path');

        return is_string($path) && $path !== '' ? mb_rtrim($path, '/') : sys_get_temp_dir().'/ranetrace-buffer';
    }

    /**
     * Seconds to keep retrying a contended spool lock. Anything unusable, and
     * anything at or below zero, means a single non-blocking attempt: waiting is
     * an optimisation, and a host that asks for no wait must not get one.
     */
    public function lockWait(): float
    {
        $wait = $this->get('batch.lock_wait', 1);

        return is_numeric($wait) && (float) $wait > 0 ? (float) $wait : 0.0;
    }

    /**
     * The whole resolved config, defaults and unknown keys included. For
     * diagnostics; the API key is returned as stored, so never log this.
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->values;
    }

    /**
     * Dot key => {env var (null when the key is not env-addressable), default,
     * coercion type}.
     *
     * @return array<string, array{env: ?string, default: mixed, type: string}>
     */
    private static function schema(): array
    {
        return [
            'enabled' => ['env' => 'RANETRACE_ENABLED', 'default' => true, 'type' => 'bool'],
            'key' => ['env' => 'RANETRACE_KEY', 'default' => '', 'type' => 'key'],
            'fingerprint_salt' => ['env' => 'RANETRACE_FINGERPRINT_SALT', 'default' => null, 'type' => 'nullable-string'],

            'base_url' => ['env' => 'RANETRACE_BASE_URL', 'default' => self::DEFAULT_BASE_URL, 'type' => 'string'],
            'environment' => ['env' => 'RANETRACE_ENVIRONMENT', 'default' => self::detectEnvironment(), 'type' => 'string'],
            'project_root' => ['env' => 'RANETRACE_PROJECT_ROOT', 'default' => self::detectProjectRoot(), 'type' => 'string'],
            'buffer_path' => ['env' => 'RANETRACE_BUFFER_PATH', 'default' => sys_get_temp_dir().'/ranetrace-buffer', 'type' => 'string'],
            'framework' => ['env' => 'RANETRACE_FRAMEWORK', 'default' => null, 'type' => 'nullable-string'],
            'framework_version' => ['env' => 'RANETRACE_FRAMEWORK_VERSION', 'default' => null, 'type' => 'nullable-string'],
            'user_resolver' => ['env' => null, 'default' => null, 'type' => 'callable'],
            'flush_on_shutdown' => ['env' => 'RANETRACE_FLUSH_ON_SHUTDOWN', 'default' => true, 'type' => 'bool'],

            'errors.enabled' => ['env' => 'RANETRACE_ERRORS_ENABLED', 'default' => true, 'type' => 'bool'],
            'errors.timeout' => ['env' => 'RANETRACE_ERRORS_TIMEOUT', 'default' => 10, 'type' => 'int'],
            'errors.capture_user_email' => ['env' => 'RANETRACE_ERRORS_CAPTURE_USER_EMAIL', 'default' => false, 'type' => 'bool'],

            'events.enabled' => ['env' => 'RANETRACE_EVENTS_ENABLED', 'default' => true, 'type' => 'bool'],
            'events.timeout' => ['env' => 'RANETRACE_EVENTS_TIMEOUT', 'default' => 10, 'type' => 'int'],

            'logging.enabled' => ['env' => 'RANETRACE_LOGGING_ENABLED', 'default' => false, 'type' => 'bool'],
            'logging.timeout' => ['env' => 'RANETRACE_LOGGING_TIMEOUT', 'default' => 10, 'type' => 'int'],
            'logging.level' => ['env' => 'RANETRACE_LOGGING_LEVEL', 'default' => 'notice', 'type' => 'string'],
            'logging.excluded_channels' => ['env' => 'RANETRACE_LOGGING_EXCLUDED_CHANNELS', 'default' => [], 'type' => 'array'],

            'javascript_errors.enabled' => ['env' => 'RANETRACE_JAVASCRIPT_ERRORS_ENABLED', 'default' => false, 'type' => 'bool'],
            'javascript_errors.timeout' => ['env' => 'RANETRACE_JAVASCRIPT_ERRORS_TIMEOUT', 'default' => 10, 'type' => 'int'],
            'javascript_errors.throttle' => ['env' => 'RANETRACE_JAVASCRIPT_ERRORS_THROTTLE', 'default' => '60,1', 'type' => 'string'],
            'javascript_errors.sample_rate' => ['env' => 'RANETRACE_JAVASCRIPT_ERRORS_SAMPLE_RATE', 'default' => 1.0, 'type' => 'float'],
            'javascript_errors.ignored_errors' => ['env' => null, 'default' => self::DEFAULT_IGNORED_JAVASCRIPT_ERRORS, 'type' => 'array'],
            'javascript_errors.capture_console_errors' => ['env' => 'RANETRACE_JAVASCRIPT_ERRORS_CAPTURE_CONSOLE_ERRORS', 'default' => false, 'type' => 'bool'],
            'javascript_errors.max_breadcrumbs' => ['env' => 'RANETRACE_JAVASCRIPT_ERRORS_MAX_BREADCRUMBS', 'default' => 20, 'type' => 'int'],
            'javascript_errors.allowed_origins' => ['env' => 'RANETRACE_JAVASCRIPT_ERRORS_ALLOWED_ORIGINS', 'default' => [], 'type' => 'array'],

            'batch.buffer_ttl' => ['env' => 'RANETRACE_BATCH_BUFFER_TTL', 'default' => 3600, 'type' => 'int'],
            'batch.max_buffer_size' => ['env' => 'RANETRACE_BATCH_MAX_BUFFER_SIZE', 'default' => 5000, 'type' => 'int'],
            'batch.lock_wait' => ['env' => 'RANETRACE_BATCH_LOCK_WAIT', 'default' => 1, 'type' => 'int'],

            'scrubbing.extra_keys' => ['env' => 'RANETRACE_SCRUBBING_EXTRA_KEYS', 'default' => [], 'type' => 'array'],

            'internal_logging.enabled' => ['env' => 'RANETRACE_INTERNAL_LOGGING_ENABLED', 'default' => true, 'type' => 'bool'],
            'internal_logging.level' => ['env' => 'RANETRACE_INTERNAL_LOGGING_LEVEL', 'default' => 'debug', 'type' => 'string'],
            'internal_logging.days' => ['env' => 'RANETRACE_INTERNAL_LOGGING_DAYS', 'default' => 14, 'type' => 'int'],
            'internal_logging.stderr_fallback' => ['env' => 'RANETRACE_INTERNAL_STDERR_FALLBACK', 'default' => true, 'type' => 'bool'],
        ];
    }

    /**
     * Deployment environment when the host does not name one. `APP_ENV` is read
     * because it is the de-facto PHP convention (Laravel, Symfony); production
     * is the safe assumption when nothing says otherwise.
     */
    private static function detectEnvironment(): string
    {
        $env = self::readEnv('APP_ENV');

        return $env === null || $env === '' ? 'production' : $env;
    }

    /**
     * Directory the reported file paths are made relative to. Located via the
     * Composer autoloader (`<root>/vendor/composer/ClassLoader.php`) rather than
     * the current working directory, which for a CLI process or a queue worker
     * is wherever the operator happened to be standing.
     */
    private static function detectProjectRoot(): string
    {
        if (class_exists(ClassLoader::class)) {
            $file = (new ReflectionClass(ClassLoader::class))->getFileName();

            if (is_string($file) && $file !== '') {
                return dirname($file, 3);
            }
        }

        $cwd = getcwd();

        return $cwd === false ? '' : $cwd;
    }

    /**
     * Raw environment value, or null when unset. `$_ENV`/`$_SERVER` are checked
     * before `getenv()` so a value injected by the host (Dotenv, FPM's `env[]`)
     * wins over a stale process environment.
     */
    private static function readEnv(string $name): ?string
    {
        $value = self::rawEnv($name);

        if ($value === null || $value === false) {
            return null;
        }

        if (is_bool($value)) {
            return 'true';
        }

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * The first of `$_ENV`, `$_SERVER` and `getenv()` that holds the name, as
     * stored. Superglobals are not typed, so the caller normalises.
     */
    private static function rawEnv(string $name): mixed
    {
        if (array_key_exists($name, $_ENV)) {
            return $_ENV[$name];
        }

        if (array_key_exists($name, $_SERVER)) {
            return $_SERVER[$name];
        }

        $value = getenv($name);

        return $value === false ? null : $value;
    }

    /**
     * Normalise a value to its declared type. Environment values always arrive
     * as strings, so this is where `'false'` stops being truthy.
     *
     * @throws InvalidArgumentException
     */
    private static function coerce(mixed $value, string $type, string $dotKey): mixed
    {
        if ($type === 'key') {
            if ($value === null) {
                return '';
            }

            if (! is_string($value)) {
                throw new InvalidArgumentException(sprintf(
                    'Ranetrace config key [%s] must be a string, %s given.',
                    $dotKey,
                    get_debug_type($value),
                ));
            }

            return $value;
        }

        if ($type === 'callable') {
            if ($value === null || is_callable($value)) {
                return $value;
            }

            throw new InvalidArgumentException(sprintf(
                'Ranetrace config key [%s] must be callable or null, %s given.',
                $dotKey,
                get_debug_type($value),
            ));
        }

        if (is_string($value)) {
            $literal = self::stringLiteral($value);

            if ($literal !== $value) {
                $value = $literal;
            }
        }

        return match ($type) {
            'bool' => self::toBool($value),
            'int' => is_numeric($value) ? (int) $value : $value,
            'float' => is_numeric($value) ? (float) $value : $value,
            'string' => is_scalar($value) ? (string) $value : $value,
            'nullable-string' => $value === null || $value === '' ? null : (is_scalar($value) ? (string) $value : $value),
            'array' => self::toArray($value),
            default => $value,
        };
    }

    /**
     * Interpret the string spellings an environment file can hold. Anything
     * unrecognised is returned untouched.
     */
    private static function stringLiteral(string $value): mixed
    {
        return match (mb_strtolower($value)) {
            'true', '(true)' => true,
            'false', '(false)' => false,
            'null', '(null)' => null,
            'empty', '(empty)' => '',
            default => $value,
        };
    }

    private static function toBool(mixed $value): mixed
    {
        if (is_bool($value)) {
            return $value;
        }

        if ($value === 1 || $value === '1') {
            return true;
        }

        if ($value === 0 || $value === '0') {
            return false;
        }

        return $value;
    }

    private static function toArray(mixed $value): mixed
    {
        if (is_array($value)) {
            return $value;
        }

        if ($value === null || $value === '') {
            return [];
        }

        if (is_string($value)) {
            return array_values(array_filter(array_map(trim(...), explode(',', $value)), static fn (string $item): bool => $item !== ''));
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $target
     */
    private static function hasDot(array $target, string $dotKey): bool
    {
        $cursor = $target;

        foreach (explode('.', $dotKey) as $segment) {
            if (! is_array($cursor) || ! array_key_exists($segment, $cursor)) {
                return false;
            }

            $cursor = $cursor[$segment];
        }

        return true;
    }

    /**
     * @param  array<string, mixed>  $target
     */
    private static function getDot(array $target, string $dotKey): mixed
    {
        $cursor = $target;

        foreach (explode('.', $dotKey) as $segment) {
            if (! is_array($cursor) || ! array_key_exists($segment, $cursor)) {
                return null;
            }

            $cursor = $cursor[$segment];
        }

        return $cursor;
    }

    /**
     * @param  array<string, mixed>  $target
     */
    private static function setDot(array &$target, string $dotKey, mixed $value): void
    {
        $segments = explode('.', $dotKey);
        $cursor = &$target;

        foreach ($segments as $index => $segment) {
            if ($index === count($segments) - 1) {
                break;
            }

            if (! isset($cursor[$segment]) || ! is_array($cursor[$segment])) {
                $cursor[$segment] = [];
            }

            $cursor = &$cursor[$segment];
        }

        $cursor[$segments[count($segments) - 1]] = $value;
    }
}
