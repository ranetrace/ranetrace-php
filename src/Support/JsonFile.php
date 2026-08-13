<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * The write half of the SDK's on-disk state: atomic JSON writes, the directory
 * they live in, and quiet deletes.
 *
 * Reading is deliberately not here. The buffer, the pause store and the worker
 * state each answer "file missing", "file empty" and "file is not the shape I
 * expect" differently: one discards and logs, one resolves to "not paused", one
 * returns an empty array. Folding those into a shared reader would force a
 * single policy on three call sites that need three, so each keeps its own.
 */
final class JsonFile
{
    /**
     * Encode a value and write it atomically.
     *
     * False covers both halves: a value that cannot be encoded and a write that
     * did not land. Callers that need to tell the two apart encode themselves
     * and call `writeEncoded()`.
     */
    public static function write(string $file, mixed $data): bool
    {
        $encoded = json_encode($data);

        if (! is_string($encoded)) {
            return false;
        }

        return self::writeEncoded($file, $encoded);
    }

    /**
     * Write already-encoded contents atomically: a temp file in the same
     * directory, then `rename` over the target. `rename` within one filesystem
     * is atomic, so a concurrent reader sees either the whole old file or the
     * whole new one, never a half-written one. The temp file shares the target's
     * directory so the rename cannot cross a filesystem boundary, and carries a
     * random suffix so two concurrent writers cannot collide on it.
     *
     * A failed write leaves nothing behind: the temp file is removed on both
     * failure paths.
     */
    public static function writeEncoded(string $file, string $contents): bool
    {
        $temp = $file.'.'.bin2hex(random_bytes(6)).'.tmp';

        if (Quietly::call(static fn (): mixed => file_put_contents($temp, $contents)) === false) {
            self::delete($temp);

            return false;
        }

        if (Quietly::call(static fn (): bool => rename($temp, $file)) !== true) {
            self::delete($temp);

            return false;
        }

        return true;
    }

    /**
     * Create the directory when it is missing, and report whether it is there
     * afterwards.
     *
     * 0770: these files hold captured payloads, which can contain request data.
     * Group-readable so a web process and a cron worker running as different
     * members of one group can share the spool; never world-readable.
     *
     * The result is read back with `is_dir` rather than taken from `mkdir`,
     * because a concurrent process creating the same directory first makes
     * `mkdir` fail on a directory that does exist.
     */
    public static function ensureDirectory(string $directory): bool
    {
        if (is_dir($directory)) {
            return true;
        }

        Quietly::call(static fn (): bool => mkdir($directory, 0770, true));

        return is_dir($directory);
    }

    /**
     * Remove a file, best effort. A file that cannot be deleted is left where it
     * is: every caller is already on a path where the failure is handled.
     */
    public static function delete(string $file): void
    {
        Quietly::call(static fn (): bool => unlink($file));
    }
}
