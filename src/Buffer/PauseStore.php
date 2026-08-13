<?php

declare(strict_types=1);

namespace Ranetrace\Php\Buffer;

use DateTimeImmutable;
use Ranetrace\Php\Config;
use Ranetrace\Php\Support\FileLock;
use Ranetrace\Php\Support\JsonFile;
use Ranetrace\Php\Support\Quietly;
use Throwable;

/**
 * Remembers that the API told us to stop, and until when.
 *
 * Ported from `ranetrace/ranetrace-laravel` (`src/Services/RanetracePauseManager.php`),
 * where the pauses lived in the cache with the entry's own expiry doing the
 * pruning. Here they live in `pauses.json` next to the buffer, so an expiry has
 * to be checked and swept explicitly.
 *
 * There is no queue in this SDK, so the Laravel job's retry ladder collapses
 * into this file. A run makes one attempt per type; whether the next run tries
 * again, and how soon, is entirely what is written here. That makes the store
 * the SDK's whole memory of a degraded endpoint, and the reason a rejected key
 * or a rate limit does not turn into a request-cycle hammering the API.
 *
 * A global pause outranks every feature pause and is checked first: a revoked
 * key is not an errors problem or an events problem, it is an everything
 * problem.
 *
 * Nothing here throws. An unreadable pause file resolves to "not paused", which
 * risks one wasted request rather than a permanently silent SDK.
 */
final class PauseStore
{
    public function __construct(private readonly Config $config) {}

    public function pauseGlobal(int $seconds, string $reason): void
    {
        $this->mutate(function (array $data) use ($seconds, $reason): array {
            $data['global'] = self::entry($seconds, $reason);

            return $data;
        });
    }

    public function pauseFeature(string $feature, int $seconds, string $reason): void
    {
        $this->mutate(function (array $data) use ($feature, $seconds, $reason): array {
            $data['features'][$feature] = self::entry($seconds, $reason);

            return $data;
        });
    }

    public function isGloballyPaused(): bool
    {
        return $this->globalPause() !== null;
    }

    public function isFeaturePaused(string $feature): bool
    {
        return $this->featurePause($feature) !== null;
    }

    /**
     * @return array{paused_until: string, reason: string}|null
     */
    public function globalPause(): ?array
    {
        return $this->read()['global'];
    }

    /**
     * @return array{paused_until: string, reason: string}|null
     */
    public function featurePause(string $feature): ?array
    {
        return $this->read()['features'][$feature] ?? null;
    }

    public function clearGlobalPause(): void
    {
        $this->mutate(function (array $data): array {
            $data['global'] = null;

            return $data;
        });
    }

    public function clearFeaturePause(string $feature): void
    {
        $this->mutate(function (array $data) use ($feature): array {
            unset($data['features'][$feature]);

            return $data;
        });
    }

    /**
     * @param  array{global: array{paused_until: string, reason: string}|null, features: array<string, array{paused_until: string, reason: string}>}  $data
     * @return array{0: array{global: array{paused_until: string, reason: string}|null, features: array<string, array{paused_until: string, reason: string}>}, 1: bool}
     */
    private static function prune(array $data): array
    {
        $changed = false;

        if ($data['global'] !== null && ! self::isActive($data['global'])) {
            $data['global'] = null;
            $changed = true;
        }

        foreach ($data['features'] as $feature => $entry) {
            if (! self::isActive($entry)) {
                unset($data['features'][$feature]);
                $changed = true;
            }
        }

        return [$data, $changed];
    }

    /**
     * @param  array{paused_until: string, reason: string}  $entry
     */
    private static function isActive(array $entry): bool
    {
        try {
            return new DateTimeImmutable($entry['paused_until']) > new DateTimeImmutable;
        } catch (Throwable) {
            // An unparseable timestamp is treated as expired: a pause nobody can
            // read the end of would otherwise be permanent.
            return false;
        }
    }

    /**
     * @return array{paused_until: string, reason: string}
     */
    private static function entry(int $seconds, string $reason): array
    {
        $until = (new DateTimeImmutable)->modify('+'.max(1, $seconds).' seconds');

        return [
            'paused_until' => $until->format('c'),
            'reason' => $reason,
        ];
    }

    private static function isEntry(mixed $candidate): bool
    {
        return is_array($candidate)
            && is_string($candidate['paused_until'] ?? null)
            && is_string($candidate['reason'] ?? null);
    }

    /**
     * Load the store with expired pauses already removed.
     *
     * Pruning happens on read so a caller never has to reason about staleness,
     * and the pruned form is written back when anything actually expired: a
     * pause file that is never rewritten would otherwise accumulate every pause
     * the SDK has ever taken.
     *
     * @return array{global: array{paused_until: string, reason: string}|null, features: array<string, array{paused_until: string, reason: string}>}
     */
    private function read(): array
    {
        [$data, $changed] = self::prune($this->load());

        if ($changed) {
            $this->mutate(static fn (array $current): array => $current);
        }

        return $data;
    }

    /**
     * @return array{global: array{paused_until: string, reason: string}|null, features: array<string, array{paused_until: string, reason: string}>}
     */
    private function load(): array
    {
        $file = $this->file();

        if (! is_file($file)) {
            return ['global' => null, 'features' => []];
        }

        $contents = Quietly::call(static fn (): mixed => file_get_contents($file));

        if (! is_string($contents) || $contents === '') {
            return ['global' => null, 'features' => []];
        }

        $decoded = json_decode($contents, true);

        if (! is_array($decoded)) {
            return ['global' => null, 'features' => []];
        }

        $features = [];

        foreach (is_array($decoded['features'] ?? null) ? $decoded['features'] : [] as $feature => $entry) {
            if (is_string($feature) && self::isEntry($entry)) {
                $features[$feature] = ['paused_until' => $entry['paused_until'], 'reason' => $entry['reason']];
            }
        }

        $global = $decoded['global'] ?? null;

        return [
            'global' => self::isEntry($global) ? ['paused_until' => $global['paused_until'], 'reason' => $global['reason']] : null,
            'features' => $features,
        ];
    }

    /**
     * Read, apply, prune and persist under an exclusive lock. The write goes
     * through `JsonFile`, so a concurrent reader sees the whole old file or the
     * whole new one.
     *
     * @param  callable(array{global: array{paused_until: string, reason: string}|null, features: array<string, array{paused_until: string, reason: string}>}): array{global: array{paused_until: string, reason: string}|null, features: array<string, array{paused_until: string, reason: string}>}  $mutation
     */
    private function mutate(callable $mutation): void
    {
        if (! JsonFile::ensureDirectory($this->directory())) {
            return;
        }

        $lock = new FileLock($this->directory().'/pauses.lock', $this->config->lockWait());
        $handle = $lock->acquire();

        if ($handle === null) {
            // Silently, and without a logger: the holder of the lock is writing
            // a pause too, and losing this one costs at most one wasted request
            // on the next run.
            return;
        }

        try {
            [$data] = self::prune($this->load());
            [$data] = self::prune($mutation($data));

            JsonFile::write($this->file(), $data);
        } finally {
            $lock->release($handle);
        }
    }

    private function file(): string
    {
        return $this->directory().'/pauses.json';
    }

    private function directory(): string
    {
        return $this->config->bufferPath();
    }
}
