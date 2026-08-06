# Ranetrace PHP SDK

Framework-agnostic PHP SDK for [Ranetrace](https://ranetrace.com): error tracking, centralized logging, event tracking and frontend JavaScript error capture. It has no framework dependency, buffers everything it captures to a local file spool, and ships the batches to the Ranetrace API from a flush you schedule, so a slow or unreachable API never slows down a request.

Using Laravel? Reach for [ranetrace/ranetrace-laravel](https://github.com/ranetrace/ranetrace-laravel) instead. It wires the same capture into the framework for you, and adds page-visit analytics.

## Installation

```bash
composer require ranetrace/ranetrace-php
```

Requires PHP 8.4 or newer, `ext-curl`, `ext-json` and Monolog 3.

## Quickstart

```php
use Monolog\Logger;
use Ranetrace\Php\Ranetrace;

$ranetrace = Ranetrace::init(['key' => getenv('RANETRACE_KEY') ?: '']);

$ranetrace->registerErrorHandlers();                       // uncaught exceptions and fatal errors

$ranetrace->report($exception);                            // a handled exception
$ranetrace->trackEvent('newsletter_signup', ['source' => 'footer']);
$ranetrace->events()->sale(orderId: 'ORDER-1', totalAmount: 89.97);

$logger = new Logger('app');
$logger->pushHandler($ranetrace->monologHandler());        // application logs
```

Captured items are buffered locally and drained when the process shuts down. On anything busier than a quiet site, flush from cron as well:

```cron
* * * * * /path/to/app/vendor/bin/ranetrace-flush >/dev/null 2>&1
```

## What it captures

- **Errors**: uncaught exceptions, fatal errors and exceptions you report yourself, with a source preview, the stack trace, allowlisted request headers, console context and the current user.
- **Logs**: any Monolog record, from `notice` up by default, with context and extra secret-scrubbed and size-capped.
- **Events**: custom business events, with a validated snake_case name and hashed visitor fingerprints. No raw IP, no cookies.
- **JavaScript errors**: a browser capture script with breadcrumbs, sampling and deduplication, posting to a relay you mount at any URL of your choosing.

Every feature has its own switch. Logging and JavaScript errors are off until you turn them on. Secrets are redacted before anything leaves your host, and capture failures are swallowed and written to the SDK's own diagnostics file, never raised into your application.

## Documentation

- [Installation and flushing](https://ranetrace.com/docs/php-installation)
- [Error tracking](https://ranetrace.com/docs/php-error-tracking)
- [Centralized logging](https://ranetrace.com/docs/php-centralized-logging)
- [Event tracking](https://ranetrace.com/docs/php-event-tracking)
- [JavaScript errors](https://ranetrace.com/docs/php-javascript-errors)

Agents working in an application that uses this package should read [AGENTS.md](AGENTS.md), which is the same surface condensed into a reference: the full config table, the required wiring and the pitfalls.

## License

The MIT license. See [LICENSE.md](LICENSE.md).
