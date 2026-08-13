<?php

declare(strict_types=1);

namespace Ranetrace\Php\Worker;

use Ranetrace\Php\Buffer\BufferInterface;
use Ranetrace\Php\Buffer\PauseStore;
use Ranetrace\Php\Config;
use Ranetrace\Php\Http\ApiClient;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\JsonFile;
use Ranetrace\Php\Support\Quietly;
use Throwable;

/**
 * Drains the buffer into the API and decides what a response means.
 *
 * Ported from `ranetrace/ranetrace-laravel` (`src/Jobs/SendBatchToRanetraceJob.php`),
 * with one structural difference that changes the shape of the whole class:
 * there is no queue here. The Laravel job could retry itself four times with
 * 60/300/900 second backoff by releasing itself back onto the queue. A plain-PHP
 * SDK has nowhere to release to, so that ladder collapses into a single rule:
 *
 *   one attempt per run, and all state between runs lives in the pause store.
 *
 * A transient failure therefore re-buffers its items and pauses the feature,
 * rather than retrying in-process. The next run (cron, or the next request's
 * shutdown flush) is the retry. This is strictly safer than an in-process retry
 * loop, which would hold a web request open while an already-degraded endpoint
 * times out repeatedly.
 *
 * The response matrix is the contract, not an implementation detail: which
 * statuses re-buffer, which drop, and which pause globally are all things the
 * server relies on the client doing. See `handle()`.
 */
final class Worker
{
    /**
     * Items per type per run. The API rejects a batch above this with 413.
     */
    public const int MAX_ITEMS_PER_RUN = 1000;

    /**
     * Soft byte budget for one request. The API hard-limits bodies to 5MB; we
     * trim to 4.5MB and re-buffer the tail, leaving headroom for the JSON
     * envelope so an oversize 413 (whole-batch discard plus a 15-minute pause)
     * cannot happen by accident.
     */
    private const int MAX_BATCH_BYTES = 4_500_000;

    /**
     * The standard back-off. Long enough that a degraded endpoint gets real
     * relief, short enough that a recovered one is retried within the buffer's
     * idle TTL.
     */
    private const int PAUSE_SECONDS = 900;

    /**
     * Floor for a 429 pause. The client result stores a missing `Retry-After`
     * as `''`, and `(int) '' === 0`; without this floor a rate-limited SDK would
     * take a zero-second pause and keep hammering the endpoint every run.
     */
    private const int RATE_LIMIT_FLOOR_SECONDS = 60;

    /**
     * Per-type transport facts. Paths are kebab-case, wrapper keys snake_case,
     * and the logs type reads its timeout from `logging.timeout` because the
     * config section is named for the feature, not the buffer.
     *
     * @var array<string, array{path: string, wrapper: string, agent: string, timeout: string}>
     */
    private const array ENDPOINTS = [
        'errors' => [
            'path' => '/errors/store',
            'wrapper' => 'errors',
            'agent' => 'Ranetrace-PHP/Errors/1.0',
            'timeout' => 'errors.timeout',
        ],
        'events' => [
            'path' => '/events/store',
            'wrapper' => 'events',
            'agent' => 'Ranetrace-PHP/Events/1.0',
            'timeout' => 'events.timeout',
        ],
        'logs' => [
            'path' => '/logs/store',
            'wrapper' => 'logs',
            'agent' => 'Ranetrace-PHP/Logs/1.0',
            'timeout' => 'logging.timeout',
        ],
        'javascript_errors' => [
            'path' => '/javascript-errors/store',
            'wrapper' => 'javascript_errors',
            'agent' => 'Ranetrace-PHP/JavaScriptErrors/1.0',
            'timeout' => 'javascript_errors.timeout',
        ],
    ];

    public function __construct(
        private readonly Config $config,
        private readonly BufferInterface $buffer,
        private readonly PauseStore $pauses,
        private readonly ApiClient $api,
        private readonly InternalLogger $log,
    ) {}

    /**
     * Drain one type, or every type when none is named.
     *
     * The buffer is drained regardless of a feature's `enabled` flag: an
     * operator who turns a feature off should still see what was already
     * captured, and leaving items to rot until the idle TTL discards them would
     * lose data that was already collected.
     */
    public function run(?string $type = null): void
    {
        try {
            $types = $this->resolveTypes($type);

            if ($types === []) {
                return;
            }

            if ($this->pauses->isGloballyPaused()) {
                $this->log->info('Skipping run, Ranetrace is globally paused', [
                    'reason' => ($this->pauses->globalPause() ?? [])['reason'] ?? null,
                ]);

                return;
            }

            foreach ($types as $bufferType) {
                // A 401 during this run pauses everything; stop immediately
                // rather than presenting a rejected key to three more endpoints.
                if ($this->pauses->isGloballyPaused()) {
                    return;
                }

                $this->drain($bufferType);
            }
        } catch (Throwable $failure) {
            // A worker that throws would surface an internal transport problem
            // through the host's error handling, and a host that reports errors
            // to Ranetrace would then try to capture it.
            $this->log->error('Worker run failed', ['exception' => $failure->getMessage()]);
        }
    }

    /**
     * Unix timestamp of the last successful batch for a type, or null. Lets a
     * status command tell a buffer that is waiting for its next run apart from
     * one whose worker is not scheduled at all.
     */
    public function lastBatchAt(string $type): ?int
    {
        $stamp = $this->readState()[$type] ?? null;

        return is_int($stamp) ? $stamp : null;
    }

    /**
     * Split a batch at the byte budget, returning [kept, deferred]. Always keeps
     * at least one item: a single over-budget item cannot be split, and the
     * per-field caps already bound individual payloads, so sending it and
     * letting the server judge beats spooling it forever.
     *
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     * @return array{0: array<int, array{id: string, data: array<string, mixed>, timestamp: int}>, 1: array<int, array{id: string, data: array<string, mixed>, timestamp: int}>}
     */
    private static function trimToByteBudget(array $items): array
    {
        $bytes = 0;

        foreach ($items as $index => $item) {
            $bytes += mb_strlen((string) json_encode($item['data']), '8bit');

            if ($index > 0 && $bytes > self::MAX_BATCH_BYTES) {
                return [array_slice($items, 0, $index), array_slice($items, $index)];
            }
        }

        return [$items, []];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private static function errorMessage(array $data, string $fallback): string
    {
        $error = $data['error'] ?? null;
        $message = is_array($error) ? ($error['message'] ?? null) : null;

        return is_string($message) && $message !== '' ? $message : $fallback;
    }

    /**
     * @return list<string>
     */
    private function resolveTypes(?string $type): array
    {
        $types = array_values(array_filter(
            $this->buffer->types(),
            static fn (string $candidate): bool => isset(self::ENDPOINTS[$candidate]),
        ));

        if ($type === null) {
            return $types;
        }

        if (! in_array($type, $types, true)) {
            $this->log->warning('Ignored a run for an unknown buffer type', ['type' => $type]);

            return [];
        }

        return [$type];
    }

    private function drain(string $type): void
    {
        if ($this->buffer->count($type) === 0) {
            return;
        }

        if ($this->pauses->isFeaturePaused($type)) {
            $this->log->debug('Skipping a paused feature', [
                'type' => $type,
                'reason' => ($this->pauses->featurePause($type) ?? [])['reason'] ?? null,
            ]);

            return;
        }

        $items = $this->buffer->take($type, self::MAX_ITEMS_PER_RUN);

        if ($items === []) {
            return;
        }

        [$items, $deferred] = self::trimToByteBudget($items);

        if ($deferred !== []) {
            $this->buffer->addItems($type, array_column($deferred, 'data'));

            $this->log->info('Deferred items to keep the batch under the size limit', [
                'type' => $type,
                'sent' => count($items),
                'deferred' => count($deferred),
            ]);
        }

        $endpoint = self::ENDPOINTS[$type];

        $result = $this->api->sendBatch(
            $endpoint['path'],
            $endpoint['wrapper'],
            $endpoint['agent'],
            $this->timeout($endpoint['timeout']),
            array_column($items, 'data'),
        );

        $this->handle($type, $items, $result);
    }

    /**
     * The response matrix. Every branch answers three questions: do the items go
     * back on the spool, does the feature (or everything) pause, and how loudly
     * is it logged.
     *
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     * @param  array{status: int, success: bool, data: array<string, mixed>, headers: array{retry-after: ?string}, error: ?string}  $result
     */
    private function handle(string $type, array $items, array $result): void
    {
        $status = $result['status'];
        $data = $result['data'];

        // Status 0 is a transport failure the API client already caught, so the
        // raw cURL message never escapes into the host application.
        if ($status === 0) {
            $this->log->error('Network error during batch send', [
                'type' => $type,
                'error' => $result['error'] ?? 'Unknown network error',
                'items_count' => count($items),
            ]);

            $this->reBuffer($type, $items);
            $this->pauses->pauseFeature($type, self::PAUSE_SECONDS, 'network');

            return;
        }

        match ($status) {
            200 => $this->handleSuccess($type, $items, $data),
            401 => $this->handleUnauthorized($type, $items, $data),
            403 => $this->handleForbidden($type, $items, $data),
            413 => $this->handlePayloadTooLarge($type, $items, $data),
            422 => $this->handleUnprocessable($type, $items, $data),
            429 => $this->handleRateLimited($type, $items, $result['headers']),
            default => $this->handleServerFailure($type, $items, $status),
        };
    }

    /**
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     * @param  array<string, mixed>  $data
     */
    private function handleSuccess(string $type, array $items, array $data): void
    {
        $this->stampLastBatch($type);

        $counters = is_array($data['items'] ?? null) ? $data['items'] : [];
        $failed = (int) ($counters['failed'] ?? 0);
        $unprocessed = (int) ($counters['unprocessed'] ?? 0);

        if ($failed > 0) {
            // Terminal by design: the server rejected these individually and
            // will reject them again, so re-sending would loop forever.
            $this->log->warning('Some items failed during processing', [
                'type' => $type,
                'received' => $counters['received'] ?? 0,
                'processed' => $counters['processed'] ?? 0,
                'ignored' => $counters['ignored'] ?? 0,
                'failed' => $failed,
            ]);
        }

        if ($unprocessed > 0) {
            $this->log->info('Some items were not processed due to timeout', [
                'type' => $type,
                'received' => $counters['received'] ?? 0,
                'processed' => $counters['processed'] ?? 0,
                'unprocessed' => $unprocessed,
            ]);

            $indexes = is_array($data['unprocessed_indexes'] ?? null) ? $data['unprocessed_indexes'] : [];
            $payloads = [];

            foreach ($indexes as $index) {
                if (is_int($index) && isset($items[$index])) {
                    $payloads[] = $items[$index]['data'];
                }
            }

            $this->buffer->addItems($type, $payloads);
        }
    }

    /**
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     * @param  array<string, mixed>  $data
     */
    private function handleUnauthorized(string $type, array $items, array $data): void
    {
        $this->log->error('API authentication failed, invalid or revoked API key', [
            'type' => $type,
            'message' => self::errorMessage($data, 'Unauthorized'),
        ]);

        // Global, not per-feature: a rejected key is not a problem with this
        // endpoint.
        $this->pauses->pauseGlobal(self::PAUSE_SECONDS, '401');
        $this->reBuffer($type, $items);
    }

    /**
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     * @param  array<string, mixed>  $data
     */
    private function handleForbidden(string $type, array $items, array $data): void
    {
        $this->log->error('API request forbidden', [
            'type' => $type,
            'message' => self::errorMessage($data, 'Forbidden'),
        ]);

        $this->pauses->pauseFeature($type, self::PAUSE_SECONDS, '403');
        $this->reBuffer($type, $items);
    }

    /**
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     * @param  array<string, mixed>  $data
     */
    private function handlePayloadTooLarge(string $type, array $items, array $data): void
    {
        // Critical because the pre-flight byte trim is supposed to make this
        // impossible: reaching here means the client is miscounting.
        $this->log->critical('Payload too large, indicates a client bug', [
            'type' => $type,
            'items_count' => count($items),
            'message' => self::errorMessage($data, 'Payload Too Large'),
        ]);

        $this->pauses->pauseFeature($type, self::PAUSE_SECONDS, '413');

        // Dropped: re-sending the same oversize batch would fail identically.
    }

    /**
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     * @param  array<string, mixed>  $data
     */
    private function handleUnprocessable(string $type, array $items, array $data): void
    {
        $this->log->error('Validation failed, indicates schema drift or malformed items', [
            'type' => $type,
            'items_count' => count($items),
            'message' => self::errorMessage($data, 'Unprocessable Entity'),
        ]);

        $this->pauses->pauseFeature($type, self::PAUSE_SECONDS, '422');

        // Dropped: the server validates the whole batch, so these items are
        // invalid and always will be.
    }

    /**
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     * @param  array{retry-after: ?string}  $headers
     */
    private function handleRateLimited(string $type, array $items, array $headers): void
    {
        $retryAfter = (int) ($headers['retry-after'] ?? 0);

        if ($retryAfter < 1) {
            $retryAfter = self::RATE_LIMIT_FLOOR_SECONDS;
        }

        $this->log->warning('Rate limit exceeded', [
            'type' => $type,
            'retry_after' => $retryAfter,
        ]);

        $this->pauses->pauseFeature($type, $retryAfter, '429');
        $this->reBuffer($type, $items);
    }

    /**
     * A 500, or any status the matrix does not name. Both are treated as
     * transient: re-buffer, back off, try again next run.
     *
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     */
    private function handleServerFailure(string $type, array $items, int $status): void
    {
        $this->log->error($status === 500 ? 'Server error during batch processing' : 'Unexpected API response status', [
            'type' => $type,
            'status' => $status,
            'items_count' => count($items),
        ]);

        $this->reBuffer($type, $items);
        $this->pauses->pauseFeature($type, self::PAUSE_SECONDS, (string) $status);
    }

    /**
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     */
    private function reBuffer(string $type, array $items): void
    {
        $this->buffer->addItems($type, array_column($items, 'data'));
    }

    private function timeout(string $dotKey): int
    {
        $timeout = $this->config->get($dotKey, 10);

        return is_numeric($timeout) && (int) $timeout > 0 ? (int) $timeout : 10;
    }

    /**
     * Record a successful drain. Kept in `state.json` beside the buffer, for the
     * same reason the buffer itself is a file: a cache store is not shared
     * across the processes that need to agree on this.
     *
     * Deliberately unlocked, unlike the buffer and the pause store. The value is
     * one timestamp per type that only ever moves forward, nothing reads it to
     * decide anything, and the atomic `rename` already rules out a torn file. A
     * lost update means a diagnostics stamp is a run behind, which is not worth
     * a lock on the success path of every batch.
     */
    private function stampLastBatch(string $type): void
    {
        $state = $this->readState();
        $state[$type] = time();

        JsonFile::write($this->stateFile(), $state);
    }

    /**
     * @return array<string, mixed>
     */
    private function readState(): array
    {
        $file = $this->stateFile();

        if (! is_file($file)) {
            return [];
        }

        $contents = Quietly::call(static fn (): mixed => file_get_contents($file));

        if (! is_string($contents) || $contents === '') {
            return [];
        }

        $decoded = json_decode($contents, true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * The state file's path, creating the buffer directory when it is missing.
     * A failed creation is not reported: the write that follows fails on its
     * own, and a missing stamp is a diagnostics gap rather than lost telemetry.
     */
    private function stateFile(): string
    {
        $directory = $this->config->bufferPath();

        JsonFile::ensureDirectory($directory);

        return $directory.'/state.json';
    }
}
