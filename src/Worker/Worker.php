<?php

declare(strict_types=1);

namespace Ranetrace\Php\Worker;

use Ranetrace\Php\Buffer\BufferInterface;
use Ranetrace\Php\Buffer\PauseStore;
use Ranetrace\Php\Config;
use Ranetrace\Php\Http\ApiClient;
use Ranetrace\Php\Http\BatchOutcome;
use Ranetrace\Php\Http\EndpointTable;
use Ranetrace\Php\Http\PauseScope;
use Ranetrace\Php\Http\ResponsePolicy;
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
     * The `{SDK}` segment of every User-Agent this package sends.
     */
    private const string SDK = 'PHP';

    /**
     * The four contracted endpoints. The table is shared with
     * `ranetrace/ranetrace-laravel`, which extends it with its own analytics
     * type; the pause lengths and the per-status decisions live beside it in
     * {@see ResponsePolicy}.
     */
    private readonly EndpointTable $endpoints;

    private readonly ResponsePolicy $policy;

    public function __construct(
        private readonly Config $config,
        private readonly BufferInterface $buffer,
        private readonly PauseStore $pauses,
        private readonly ApiClient $api,
        private readonly InternalLogger $log,
    ) {
        $this->endpoints = EndpointTable::contract();
        $this->policy = new ResponsePolicy;
    }

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
     * @return list<string>
     */
    private function resolveTypes(?string $type): array
    {
        $types = array_values(array_filter(
            $this->buffer->types(),
            fn (string $candidate): bool => $this->endpoints->has($candidate),
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

        $endpoint = $this->endpoints->get($type);

        $result = $this->api->sendBatch(
            $endpoint->path,
            $endpoint->wrapper,
            $endpoint->userAgent(self::SDK),
            $this->timeout($endpoint->timeoutKey),
            array_column($items, 'data'),
        );

        $this->handle($type, $items, $result);
    }

    /**
     * Act on one response.
     *
     * What each status MEANS lives in {@see ResponsePolicy}, shared with
     * `ranetrace/ranetrace-laravel` so the two SDKs cannot drift on it. What is
     * left here is this worker's own half: the diagnostics wording, the
     * file-backed pause store, and the fact that a transient failure pauses on
     * the spot rather than being retried, because there is no queue to release
     * to and the next run is the retry. {@see BatchOutcome::$transient} is
     * therefore read by the Laravel job and deliberately ignored here.
     *
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     * @param  array{status: int, success: bool, data: array<string, mixed>, headers: array{retry-after: ?string}, error: ?string}  $result
     */
    private function handle(string $type, array $items, array $result): void
    {
        $outcome = $this->policy->decide($result);

        $this->logOutcome($type, $items, $result, $outcome);

        if ($outcome->stampLastBatch) {
            $this->stampLastBatch($type);
        }

        if ($outcome->rebuffer) {
            $this->reBuffer($type, $items);
        }

        if ($outcome->counters?->hasUnprocessed() === true) {
            $this->buffer->addItems($type, $outcome->unprocessedPayloads($items));
        }

        $seconds = $outcome->pauseSeconds ?? ResponsePolicy::PAUSE_SECONDS;

        match ($outcome->pauseScope) {
            // Global, not per-feature: a rejected key is not a problem with
            // this endpoint.
            PauseScope::Everything => $this->pauses->pauseGlobal($seconds, $outcome->reason),
            PauseScope::Feature => $this->pauses->pauseFeature($type, $seconds, $outcome->reason),
            PauseScope::None => null,
        };
    }

    /**
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items
     * @param  array{status: int, success: bool, data: array<string, mixed>, headers: array{retry-after: ?string}, error: ?string}  $result
     */
    private function logOutcome(string $type, array $items, array $result, BatchOutcome $outcome): void
    {
        $data = $result['data'];

        match ($outcome->status) {
            // Status 0 is a transport failure the API client already caught, so
            // the raw cURL message never escapes into the host application.
            0 => $this->log->error('Network error during batch send', [
                'type' => $type,
                'error' => $result['error'] ?? 'Unknown network error',
                'items_count' => count($items),
            ]),
            200 => $this->logSuccess($type, $outcome),
            401 => $this->log->error('API authentication failed, invalid or revoked API key', [
                'type' => $type,
                'message' => ResponsePolicy::errorMessage($data, 'Unauthorized'),
            ]),
            403 => $this->log->error('API request forbidden', [
                'type' => $type,
                'message' => ResponsePolicy::errorMessage($data, 'Forbidden'),
            ]),
            // Critical because the pre-flight byte trim is supposed to make a
            // 413 impossible: reaching here means the client is miscounting.
            413 => $this->log->critical('Payload too large, indicates a client bug', [
                'type' => $type,
                'items_count' => count($items),
                'message' => ResponsePolicy::errorMessage($data, 'Payload Too Large'),
            ]),
            422 => $this->log->error('Validation failed, indicates schema drift or malformed items', [
                'type' => $type,
                'items_count' => count($items),
                'message' => ResponsePolicy::errorMessage($data, 'Unprocessable Entity'),
            ]),
            429 => $this->log->warning('Rate limit exceeded', [
                'type' => $type,
                'retry_after' => $outcome->pauseSeconds,
            ]),
            default => $this->log->error(
                $outcome->status === 500 ? 'Server error during batch processing' : 'Unexpected API response status',
                [
                    'type' => $type,
                    'status' => $outcome->status,
                    'items_count' => count($items),
                ]
            ),
        };
    }

    private function logSuccess(string $type, BatchOutcome $outcome): void
    {
        $counters = $outcome->counters;

        if ($counters === null) {
            return;
        }

        if ($counters->hasFailures()) {
            // Terminal by design: the server rejected these individually and
            // will reject them again, so re-sending would loop forever.
            $this->log->warning('Some items failed during processing', [
                'type' => $type,
                'received' => $counters->received,
                'processed' => $counters->processed,
                'ignored' => $counters->ignored,
                'failed' => $counters->failed,
            ]);
        }

        if ($counters->hasUnprocessed()) {
            $this->log->info('Some items were not processed due to timeout', [
                'type' => $type,
                'received' => $counters->received,
                'processed' => $counters->processed,
                'unprocessed' => $counters->unprocessed,
            ]);
        }
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
