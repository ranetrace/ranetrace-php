# Ranetrace PHP SDK

Framework-agnostic PHP SDK for [Ranetrace](https://ranetrace.com): error tracking, logging, event tracking and frontend JavaScript error capture. It has no framework dependency, buffers everything it captures to a local file spool, and ships the batches to the Ranetrace API from a worker you schedule, so a slow or unreachable API never slows down a request.

```bash
composer require ranetrace/ranetrace-php
```

Using Laravel? Reach for [ranetrace/ranetrace-laravel](https://github.com/ranetrace/ranetrace-laravel) instead. It wires the same capture into the framework for you.

Docs to follow.

## License

The MIT license. See [LICENSE.md](LICENSE.md).
