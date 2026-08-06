<?php

declare(strict_types=1);

namespace Ranetrace\Php\Buffer;

use Ranetrace\Php\Config;
use Ranetrace\Php\Support\InternalLogger;
use Throwable;

/**
 * The default spool: one JSON file per buffer type, guarded by `flock`.
 *
 * Ported from `ranetrace/ranetrace-laravel` (`src/Services/RanetraceBatchBuffer.php`),
 * which spooled into the host application's cache store. That is exactly the
 * design this class exists to replace. A cache store is per-process for the
 * `array` driver and per-machine for the `file` driver, so on a multi-worker
 * PHP-FPM box the Laravel SDK could buffer an item in one process that no other
 * process could ever drain. A file on disk is the smallest thing every PHP
 * process on a machine can agree on.
 *
 * Three invariants carry the correctness:
 *
 * 1. Every read-modify-write happens under an exclusive `flock` on a sidecar
 *    `.lock` file. The lock is on a sidecar rather than the data file because
 *    writes replace the data file by `rename`, which swaps the inode out from
 *    under any lock held on it.
 * 2. Writes are temp-file-plus-rename, so a concurrent reader sees either the
 *    whole old buffer or the whole new one, never a half-written file.
 * 3. `take()` removes items before anything is sent. Delivery is therefore
 *    at-least-once: a failed send re-buffers through `addItems()`, and the worst
 *    case is a duplicate rather than a silent loss.
 *
 * No HTTP ever happens inside the lock; critical sections are sub-millisecond.
 */
final class FileBuffer implements BufferInterface
{
    /**
     * Every type this SDK spools. `page_visits` is deliberately absent: website
     * analytics needs request middleware, which a framework-agnostic SDK cannot
     * install.
     *
     * @var list<string>
     */
    private const array TYPES = ['errors', 'events', 'logs', 'javascript_errors'];

    /**
     * Poll interval while waiting for a contended lock. `flock()` has no
     * timeout, so a blocking wait is spelled as non-blocking attempts plus
     * sleeps.
     */
    private const int LOCK_RETRY_MICROSECONDS = 10_000;

    public function __construct(
        private readonly Config $config,
        private readonly InternalLogger $log,
    ) {}

    public function addItem(string $type, array $data): bool
    {
        return $this->addItems($type, [$data]);
    }

    public function addItems(string $type, array $items): bool
    {
        if (! $this->isKnownType($type)) {
            return false;
        }

        if ($items === []) {
            return true;
        }

        if (! $this->ensureDirectory()) {
            return false;
        }

        $handle = $this->lock($type);

        if ($handle === null) {
            // The item is not buffered. Callers treat a false return as a silent
            // drop after internal logging rather than raising: contention here is
            // rare, and the capture path must never break the host application.
            $this->log->warning('Could not acquire buffer lock to add items', [
                'type' => $type,
                'count' => count($items),
            ]);

            return false;
        }

        try {
            $buffer = $this->read($type);

            foreach ($items as $data) {
                $buffer[] = [
                    'id' => self::uuid(),
                    'data' => $data,
                    'timestamp' => time(),
                ];
            }

            $maxSize = $this->maxBufferSize();

            if (count($buffer) > $maxSize) {
                $dropped = count($buffer) - $maxSize;

                // Keep the newest. Under sustained overflow the recent past
                // describes the incident better than the start of the backlog.
                $buffer = array_slice($buffer, -$maxSize);

                $this->logOverflowOnce($type, $dropped, $maxSize);
            }

            return $this->write($type, $buffer);
        } finally {
            $this->unlock($handle);
        }
    }

    public function take(string $type, int $limit): array
    {
        if (! $this->isKnownType($type) || $limit < 1) {
            return [];
        }

        if (! $this->ensureDirectory()) {
            return [];
        }

        $handle = $this->lock($type);

        if ($handle === null) {
            // Harmless for a drain: the items stay spooled and the next run
            // picks them up.
            $this->log->warning('Could not acquire buffer lock to take items', ['type' => $type]);

            return [];
        }

        try {
            $buffer = $this->read($type);

            if ($buffer === []) {
                return [];
            }

            $taken = array_slice($buffer, 0, $limit);
            $remaining = array_slice($buffer, $limit);

            if (count($remaining) < $this->maxBufferSize()) {
                // The drain ended the overflow cycle, so the next overflow is
                // worth logging again.
                $this->clearOverflowFlag($type);
            }

            if (! $this->write($type, $remaining)) {
                // The remainder could not be persisted, so the file still holds
                // everything. Handing the caller items that are also still on
                // disk would duplicate them on the next run; returning nothing
                // loses nothing.
                $this->log->error('Could not persist buffer after take, items left in place', ['type' => $type]);

                return [];
            }

            return $taken;
        } finally {
            $this->unlock($handle);
        }
    }

    public function count(string $type): int
    {
        if (! $this->isKnownType($type)) {
            return 0;
        }

        return count($this->read($type));
    }

    public function types(): array
    {
        return self::TYPES;
    }

    /**
     * Unix timestamp of the oldest spooled item, or null when the buffer is
     * empty. Items are appended in arrival order and drained FIFO, so the head
     * is always the oldest. Lets diagnostics tell a buffer that is simply
     * waiting for its next drain apart from one that is genuinely stalled.
     */
    public function oldestTimestamp(string $type): ?int
    {
        $buffer = $this->isKnownType($type) ? $this->read($type) : [];

        return $buffer === [] ? null : $buffer[0]['timestamp'];
    }

    /**
     * Discard everything spooled for a type. Used by the idle-TTL sweep and
     * available to operators who need to abandon a poisoned backlog.
     */
    public function clear(string $type): void
    {
        if (! $this->isKnownType($type)) {
            return;
        }

        $this->quietly(fn (): bool => unlink($this->file($type)));
        $this->clearOverflowFlag($type);
    }

    /**
     * A random version-4 UUID. The envelope id only has to be unique, so this
     * avoids a dependency on `ramsey/uuid` for one string.
     */
    private static function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

        $hex = bin2hex($bytes);

        return sprintf(
            '%s-%s-%s-%s-%s',
            mb_substr($hex, 0, 8),
            mb_substr($hex, 8, 4),
            mb_substr($hex, 12, 4),
            mb_substr($hex, 16, 4),
            mb_substr($hex, 20, 12),
        );
    }

    private static function isEnvelope(mixed $candidate): bool
    {
        return is_array($candidate)
            && is_string($candidate['id'] ?? null)
            && is_array($candidate['data'] ?? null)
            && is_int($candidate['timestamp'] ?? null);
    }

    /**
     * Read the spool for a type, dropping it wholesale when it has gone stale.
     *
     * The idle TTL is expressed as the data file's mtime, which every write
     * refreshes because writes land through `rename` of a freshly written temp
     * file. A buffer nobody has drained for an hour describes a host whose
     * worker is not running; keeping it would mean eventually shipping hours-old
     * telemetry that no longer matches anything.
     *
     * @return array<int, array{id: string, data: array<string, mixed>, timestamp: int}>
     */
    private function read(string $type): array
    {
        $file = $this->file($type);

        clearstatcache(true, $file);

        if (! is_file($file)) {
            return [];
        }

        if ($this->isExpired($file)) {
            $this->log->info('Discarded a buffer that exceeded its idle TTL', [
                'type' => $type,
                'ttl' => $this->bufferTtl(),
            ]);

            $this->quietly(fn (): bool => unlink($file));
            $this->clearOverflowFlag($type);

            return [];
        }

        $contents = $this->quietly(fn (): mixed => file_get_contents($file));

        if (! is_string($contents) || $contents === '') {
            return [];
        }

        $decoded = json_decode($contents, true);

        if (! is_array($decoded)) {
            $this->log->error('Buffer file was unreadable and has been discarded', ['type' => $type]);

            $this->quietly(fn (): bool => unlink($file));

            return [];
        }

        /** @var array<int, array{id: string, data: array<string, mixed>, timestamp: int}> $envelopes */
        $envelopes = array_values(array_filter($decoded, self::isEnvelope(...)));

        return $envelopes;
    }

    /**
     * Persist a buffer atomically: write a temp file in the same directory, then
     * `rename` it over the target. `rename` within one filesystem is atomic, so
     * a concurrent reader never observes a partial write.
     *
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $envelopes
     */
    private function write(string $type, array $envelopes): bool
    {
        $file = $this->file($type);

        if ($envelopes === []) {
            $this->quietly(fn (): bool => unlink($file));

            return true;
        }

        $encoded = json_encode($envelopes);

        if (! is_string($encoded)) {
            $this->log->error('Could not encode buffer contents', ['type' => $type]);

            return false;
        }

        $temp = $file.'.'.bin2hex(random_bytes(6)).'.tmp';

        if ($this->quietly(fn (): mixed => file_put_contents($temp, $encoded)) === false) {
            $this->quietly(fn (): bool => unlink($temp));

            return false;
        }

        if ($this->quietly(fn (): bool => rename($temp, $file)) !== true) {
            $this->quietly(fn (): bool => unlink($temp));

            return false;
        }

        return true;
    }

    /**
     * Log an overflow drop at most once per overflow cycle. A flag file next to
     * the buffer records that the cycle is open; `take()` clears it once a drain
     * brings the buffer back under capacity. Without this, a host that is
     * overflowing is also the host whose disk fills with identical log lines.
     */
    private function logOverflowOnce(string $type, int $dropped, int $maxSize): void
    {
        $flag = $this->overflowFlagFile($type);

        if (is_file($flag)) {
            return;
        }

        $this->quietly(fn (): mixed => file_put_contents($flag, (string) time()));

        $this->log->warning('Ranetrace buffer overflow — oldest items dropped', [
            'type' => $type,
            'dropped' => $dropped,
            'max' => $maxSize,
        ]);
    }

    private function clearOverflowFlag(string $type): void
    {
        $flag = $this->overflowFlagFile($type);

        if (is_file($flag)) {
            $this->quietly(fn (): bool => unlink($flag));
        }
    }

    /**
     * Take the exclusive lock for a type, waiting up to `batch.lock_wait`
     * seconds. `flock()` offers no timeout, so a bounded wait is spelled as
     * non-blocking attempts with a short sleep between them. A wait of 0 means a
     * single attempt.
     *
     * @return resource|null
     */
    private function lock(string $type): mixed
    {
        $handle = $this->quietly(fn (): mixed => fopen($this->lockFile($type), 'c'));

        if (! is_resource($handle)) {
            return null;
        }

        $deadline = microtime(true) + $this->lockWait();

        while (true) {
            if ($this->quietly(fn (): bool => flock($handle, LOCK_EX | LOCK_NB)) === true) {
                return $handle;
            }

            if (microtime(true) >= $deadline) {
                $this->quietly(fn (): bool => fclose($handle));

                return null;
            }

            usleep(self::LOCK_RETRY_MICROSECONDS);
        }
    }

    /**
     * @param  resource  $handle
     */
    private function unlock(mixed $handle): void
    {
        $this->quietly(function () use ($handle): bool {
            flock($handle, LOCK_UN);

            return fclose($handle);
        });
    }

    private function ensureDirectory(): bool
    {
        $directory = $this->directory();

        if (is_dir($directory)) {
            return true;
        }

        // 0770: the buffer holds captured payloads, which can contain request
        // data. Group-readable so a web process and a cron worker running as
        // different members of one group can share it; never world-readable.
        $this->quietly(fn (): bool => mkdir($directory, 0770, true));

        if (is_dir($directory)) {
            return true;
        }

        $this->log->error('Buffer directory is not writable', ['path' => $directory]);

        return false;
    }

    private function isExpired(string $file): bool
    {
        $ttl = $this->bufferTtl();

        if ($ttl < 1) {
            return false;
        }

        $modified = $this->quietly(fn (): mixed => filemtime($file));

        return is_int($modified) && $modified + $ttl < time();
    }

    private function isKnownType(string $type): bool
    {
        if (in_array($type, self::TYPES, true)) {
            return true;
        }

        // Default reject: an unknown type would also be an unvalidated path
        // segment in the buffer directory.
        $this->log->warning('Ignored an unknown buffer type', ['type' => $type]);

        return false;
    }

    private function file(string $type): string
    {
        return $this->directory().'/'.$type.'.json';
    }

    private function lockFile(string $type): string
    {
        return $this->directory().'/'.$type.'.lock';
    }

    private function overflowFlagFile(string $type): string
    {
        return $this->directory().'/'.$type.'.overflow';
    }

    private function directory(): string
    {
        $path = $this->config->get('buffer_path');

        return is_string($path) && $path !== '' ? mb_rtrim($path, '/') : sys_get_temp_dir().'/ranetrace-buffer';
    }

    private function maxBufferSize(): int
    {
        $max = $this->config->get('batch.max_buffer_size', 5000);

        return is_numeric($max) && (int) $max > 0 ? (int) $max : 5000;
    }

    private function bufferTtl(): int
    {
        $ttl = $this->config->get('batch.buffer_ttl', 3600);

        return is_numeric($ttl) ? (int) $ttl : 3600;
    }

    private function lockWait(): float
    {
        $wait = $this->config->get('batch.lock_wait', 1);

        return is_numeric($wait) && (float) $wait > 0 ? (float) $wait : 0.0;
    }

    /**
     * Run a filesystem call with PHP's error reporting muted.
     *
     * The `@` operator is not enough: it still invokes whatever error handler the
     * host installed, and an unwritable buffer directory would then surface as a
     * warning in the host's logs. Worse, a host that routes its logs back into
     * Ranetrace would capture that warning, buffer it, and fail to write it for
     * the same reason. Every failure here is expected and handled by a return
     * value instead.
     */
    private function quietly(callable $callback): mixed
    {
        set_error_handler(static fn (): bool => true);

        try {
            return $callback();
        } catch (Throwable) {
            return false;
        } finally {
            restore_error_handler();
        }
    }
}
