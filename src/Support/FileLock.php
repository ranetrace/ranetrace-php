<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * An exclusive `flock` on a sidecar lock file, with a bounded wait.
 *
 * The lock lives on a sidecar rather than on the data file it guards because
 * writes replace the data file by `rename`, which swaps the inode out from
 * under any lock held on it. A sidecar keeps one stable inode every process can
 * agree on.
 *
 * The wait is spelled as non-blocking attempts plus short sleeps because
 * `flock()` offers no timeout: `LOCK_EX` alone would block forever on a
 * contended file, which in a web request is worse than dropping the item. A
 * wait of 0 means a single attempt.
 *
 * Nothing here throws. A lock that cannot be taken resolves to null, and every
 * caller treats that as "skip this run" rather than as an error.
 */
final class FileLock
{
    /**
     * Poll interval while waiting for a contended lock.
     */
    private const int RETRY_MICROSECONDS = 10_000;

    /**
     * @param  string  $path  The sidecar lock file, created on demand.
     * @param  float  $wait  Seconds to keep retrying before giving up.
     */
    public function __construct(
        private readonly string $path,
        private readonly float $wait,
    ) {}

    /**
     * Take the lock, or return null when it stays contended for the whole wait.
     *
     * @return resource|null The open handle, which the caller must hand back to `release()`.
     */
    public function acquire(): mixed
    {
        $handle = Quietly::call(fn (): mixed => fopen($this->path, 'c'));

        if (! is_resource($handle)) {
            return null;
        }

        $deadline = microtime(true) + $this->wait;

        while (true) {
            if (Quietly::call(static fn (): bool => flock($handle, LOCK_EX | LOCK_NB)) === true) {
                return $handle;
            }

            if (microtime(true) >= $deadline) {
                Quietly::call(static fn (): bool => fclose($handle));

                return null;
            }

            usleep(self::RETRY_MICROSECONDS);
        }
    }

    /**
     * @param  resource  $handle
     */
    public function release(mixed $handle): void
    {
        Quietly::call(static function () use ($handle): bool {
            flock($handle, LOCK_UN);

            return fclose($handle);
        });
    }
}
