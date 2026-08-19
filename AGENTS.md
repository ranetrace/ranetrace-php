# Ranetrace PHP SDK: agent reference

Quick reference for agents working in an application that uses `ranetrace/ranetrace-php`. For working **on** this package, read `CLAUDE.md` instead.

## What this package is

`ranetrace/ranetrace-php` is the framework-agnostic PHP SDK for [Ranetrace](https://ranetrace.com). It captures errors, log records, custom events and browser JavaScript errors, buffers them to a local file spool, and ships them to the Ranetrace API in batches.

- Namespace `Ranetrace\Php\`. The one class a host touches is `Ranetrace\Php\Ranetrace`.
- Requires PHP `^8.4`, `ext-curl`, `ext-json`, `monolog/monolog ^3`, `psr/log ^3`.
- No queue, no container, no framework. Anything it cannot discover is configuration.
- Website analytics is **not** in this SDK. It needs request middleware and stays a `ranetrace/ranetrace-laravel` feature.
- In a Laravel application, use `ranetrace/ranetrace-laravel` instead. Never both.

## Install and bootstrap

```bash
composer require ranetrace/ranetrace-php
```

```php
use Monolog\Logger;
use Ranetrace\Php\Ranetrace;

$ranetrace = Ranetrace::init([
    'key' => getenv('RANETRACE_KEY') ?: '',
    'environment' => getenv('APP_ENV') ?: 'production',
    'framework' => 'Symfony',              // optional, both default to null
    'framework_version' => \Symfony\Component\HttpKernel\Kernel::VERSION,
    'user_resolver' => static fn (): ?array => ['id' => 1, 'email' => 'a@b.test'],
]);

$ranetrace->registerErrorHandlers();       // required for automatic capture

$logger = new Logger('app');
$logger->pushHandler($ranetrace->monologHandler());
```

`Ranetrace::init()` stores the instance; `Ranetrace::instance()` returns it or `null`. `new Ranetrace([...])` builds one without the static. Config keys are nested arrays (`'logging' => ['enabled' => true]`) and every key falls back to its `RANETRACE_*` environment variable, then to the default.

## Public API

| Call | Does |
|---|---|
| `Ranetrace::init(array $config): self` | Build and remember the instance. |
| `Ranetrace::instance(): ?self` | The remembered instance, or null. |
| `registerErrorHandlers(): void` | Install the exception and fatal-shutdown handlers. Idempotent. |
| `report(Throwable $e): void` | Capture one throwable. Never throws. |
| `trackEvent(string $name, array $properties = [], int\|string\|null $userId = null, bool $validate = true): void` | Buffer one event. Throws `InvalidArgumentException` on an invalid name. |
| `events(): Events\EventTracker` | `sale()`, `productAddedToCart()`, `userRegistered()`, `userLoggedIn()`, `pageView()`, `custom()`, `customUnsafe()`. |
| `monologHandler(int\|string\|Level\|null $level = null): Logging\RanetraceHandler` | Monolog handler; default level is `logging.level` (`notice`), not Monolog's `debug`. |
| `javascriptSnippet(array $options = []): string` | `<script>` tag. `endpoint` is **required** (throws without it); `nonce` optional. Empty string when the feature is off. |
| `relay(): JavaScript\Relay` | `handle()` for superglobals (reads `php://input` + `$_SERVER`, echoes JSON), `handleRequest(array $server, array $payload): RelayResponse` for a framework. |
| `flush(?string $type = null): void` | Drain the buffer now. `flushQuietly()` is the never-throw variant. |
| `config(): Config`, `buffer(): Buffer\FileBuffer`, `pauses(): Buffer\PauseStore` | Diagnostics. |
| `withHttpClient(HttpClientInterface $http): self` | Replace the transport (proxy, mTLS, tests). |

Event names must be snake_case, 3 to 50 characters, starting with a letter: `/^[a-z][a-z0-9_]*$/`.

## Environment variables

| Variable | Config key | Default |
|---|---|---|
| `RANETRACE_ENABLED` | `enabled` | `true` |
| `RANETRACE_KEY` | `key` | empty (nothing is captured without it) |
| `RANETRACE_BASE_URL` | `base_url` | `https://api.ranetrace.com/v1` |
| `RANETRACE_ENVIRONMENT` | `environment` | `APP_ENV`, else `production` |
| `RANETRACE_PROJECT_ROOT` | `project_root` | resolved from Composer's autoloader location |
| `RANETRACE_BUFFER_PATH` | `buffer_path` | `sys_get_temp_dir().'/ranetrace-buffer'` |
| `RANETRACE_FRAMEWORK` | `framework` | `null` |
| `RANETRACE_FRAMEWORK_VERSION` | `framework_version` | `null` |
| `RANETRACE_FINGERPRINT_SALT` | `fingerprint_salt` | falls back to the API key |
| `RANETRACE_FLUSH_ON_SHUTDOWN` | `flush_on_shutdown` | `true` |
| (config only) | `user_resolver` | `null`, must be callable returning `?array{id, email}` |
| `RANETRACE_ERRORS_ENABLED` | `errors.enabled` | `true` |
| `RANETRACE_ERRORS_TIMEOUT` | `errors.timeout` | `10` |
| `RANETRACE_ERRORS_CAPTURE_USER_EMAIL` | `errors.capture_user_email` | `false` |
| `RANETRACE_EVENTS_ENABLED` | `events.enabled` | `true` |
| `RANETRACE_EVENTS_TIMEOUT` | `events.timeout` | `10` |
| `RANETRACE_LOGGING_ENABLED` | `logging.enabled` | **`false`** |
| `RANETRACE_LOGGING_LEVEL` | `logging.level` | `notice` |
| `RANETRACE_LOGGING_EXCLUDED_CHANNELS` | `logging.excluded_channels` | `[]` (csv in env) |
| `RANETRACE_LOGGING_TIMEOUT` | `logging.timeout` | `10` |
| `RANETRACE_JAVASCRIPT_ERRORS_ENABLED` | `javascript_errors.enabled` | **`false`** |
| `RANETRACE_JAVASCRIPT_ERRORS_SAMPLE_RATE` | `javascript_errors.sample_rate` | `1.0` |
| `RANETRACE_JAVASCRIPT_ERRORS_CAPTURE_CONSOLE_ERRORS` | `javascript_errors.capture_console_errors` | `false` |
| `RANETRACE_JAVASCRIPT_ERRORS_MAX_BREADCRUMBS` | `javascript_errors.max_breadcrumbs` | `20` |
| `RANETRACE_JAVASCRIPT_ERRORS_ALLOWED_ORIGINS` | `javascript_errors.allowed_origins` | `[]` (csv in env) |
| `RANETRACE_JAVASCRIPT_ERRORS_THROTTLE` | `javascript_errors.throttle` | `'60,1'` (carried for parity, **not enforced**) |
| `RANETRACE_JAVASCRIPT_ERRORS_TIMEOUT` | `javascript_errors.timeout` | `10` |
| (config only) | `javascript_errors.ignored_errors` | 15 built-in noise patterns |
| `RANETRACE_BATCH_BUFFER_TTL` | `batch.buffer_ttl` | `3600` |
| `RANETRACE_BATCH_MAX_BUFFER_SIZE` | `batch.max_buffer_size` | `5000` |
| `RANETRACE_BATCH_LOCK_WAIT` | `batch.lock_wait` | `1` |
| `RANETRACE_SCRUBBING_EXTRA_KEYS` | `scrubbing.extra_keys` | `[]` (csv in env, added to built-ins) |
| `RANETRACE_INTERNAL_LOGGING_ENABLED` | `internal_logging.enabled` | `true` |
| `RANETRACE_INTERNAL_LOGGING_LEVEL` | `internal_logging.level` | `debug` |
| `RANETRACE_INTERNAL_LOGGING_DAYS` | `internal_logging.days` | `14` |
| `RANETRACE_INTERNAL_STDERR_FALLBACK` | `internal_logging.stderr_fallback` | `true` |

`enabled()` requires all three: the master switch, the feature's own switch, and a non-empty key.

## Required wiring

Two things are not automatic. Without either, the SDK captures or delivers nothing.

1. **`$ranetrace->registerErrorHandlers();`** installs `set_exception_handler` (chains the previous handler; rethrows when there was none, so PHP's own uncaught-exception output and non-zero exit survive) and a `register_shutdown_function` for fatals (`E_ERROR`, `E_PARSE`, `E_CORE_ERROR`, `E_COMPILE_ERROR`). `set_error_handler` is deliberately not installed: notices, warnings and deprecations are out of scope. `report()` works without any of this.
2. **A flush path.** Captured items sit in the file spool until a flush ships them. `flush_on_shutdown` is `true` by default, which covers the simplest deployment. For steady throughput add cron:

```cron
* * * * * /path/to/app/vendor/bin/ranetrace-flush >/dev/null 2>&1
```

Every minute matches the API's 60 requests per minute per endpoint per key; one run sends at most one batch per type. The binary is configured **entirely from the environment** (a cron entry has no bootstrap), sets `flush_on_shutdown => false` for itself, prints nothing on success, exits `1` when it could not run, and takes `--type=errors|events|logs|javascript_errors`. Shutdown flush and cron compose safely: the spool is locked and drained atomically.

A spool that goes untouched for `batch.buffer_ttl` (3600s), neither written to nor drained, is discarded, so "no cron and almost no traffic" means data loss.

## JavaScript relay

The host mounts it; the SDK registers no routes.

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['REQUEST_URI'] === '/ranetrace/js-errors') {
    $ranetrace->relay()->handle();

    exit;
}
```

```php
echo $ranetrace->javascriptSnippet(['endpoint' => '/ranetrace/js-errors', 'nonce' => $cspNonce]);
```

- CSRF is replaced by a same-origin check: `Origin`, else `Referer`, must match `Host`/`SERVER_NAME` or appear in `javascript_errors.allowed_origins` (full origin or bare authority both accepted). Neither header present is allowed. The script sends no `X-CSRF-TOKEN` here because it is given no token; it can send one, and does when `ranetrace/ranetrace-laravel` renders the same script.
- `JavaScript\CaptureScript::withConfig(array $config): string` is the seam another SDK builds on: the bare script body with the given runtime config substituted, no `<script>` tag around it. An application host wants `javascriptSnippet()` above instead.
- Set `$_SERVER['RANETRACE_SESSION_ID']` to a per-visit id if you want per-visit grouping. It is HMAC-hashed, never stored raw.
- `user_agent`, `environment`, `user_id` and `session_id` are server-added and never read from the posted payload.
- Statuses: 200 (received, ignored by pattern, or sampled out), 403 (disabled or origin rejected), 422 (validation), 500 (internal). Never throws.

## Common pitfalls

- **`buffer_path` on multi-worker or multi-user hosts.** The directory is created `0770`. Web processes and the cron flush must share access to the same directory, or each spools telemetry the other never drains. Multiple machines each need their own flush path. `array`-style per-process stores are exactly the problem this file buffer exists to avoid.
- **The wire contract is strict.** The API does strict field-set matching: one extra, missing or wrongly typed key rejects the **whole batch** with 422, drops every item in it and pauses the feature for 15 minutes. Never add fields to a payload, and never "enrich" a captured item on the way out. The exact shape per capture type ships in the package's `contract/` directory, readable through `Ranetrace\Php\Contract\WireContract`.
- **A captured item has a byte budget.** Each item is held to 70 KB JSON-encoded on its way to the buffer. Over that, string fields above 8 KB are cut with a `... (truncated)` suffix and array fields above 8 KB (event `properties`, log `context`, JS-error `breadcrumbs`) are replaced wholesale with a `_truncated` marker; an item still over budget after that is dropped, and only the internal log records it. So do not hand the SDK a megabyte of event properties or log context expecting to read it back in the dashboard: pass an identifier and leave the bulk where it already lives.
- **The JS relay needs host rate limiting.** It is a public unauthenticated POST and this SDK does not throttle it. `javascript_errors.throttle` is config-surface parity only. Put a limit in the framework, web server or CDN; 60/minute per client matches the Laravel SDK.
- **Internal diagnostics are isolated on purpose.** The SDK writes its own diagnostics to `{buffer_path}/internal-YYYY-MM-DD.log`, never through the host logger, so a failing send cannot be captured, buffered and re-sent in a loop. Do not route them into the application logger, and do not add anything to `excluded_channels` for loop protection.
- **Two failure postures.** Malformed config throws from the constructor (non-string `key`, non-callable `user_resolver`), and an invalid event name throws from `trackEvent()`. Everything else on a capture path is caught, written to the internal log and dropped. Do not add try/catch around capture calls expecting to see failures there.
- **`errors.capture_user_email` is off by default.** Only the user id travels until it is turned on.
- **Both switches are needed.** `RANETRACE_ENABLED=true`, the feature flag, and a non-empty `RANETRACE_KEY`.

## Docs

- https://ranetrace.com/docs/php-installation
- https://ranetrace.com/docs/php-error-tracking
- https://ranetrace.com/docs/php-centralized-logging
- https://ranetrace.com/docs/php-event-tracking
- https://ranetrace.com/docs/php-javascript-errors
