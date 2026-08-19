<?php

declare(strict_types=1);

namespace Ranetrace\Php\Http;

/**
 * The per-item tallies a 200 carries back.
 *
 * Absent counters are zero: the server omits `ignored`, `failed` and
 * `unprocessed` when they are zero, so every one of them is read with a zero
 * default rather than expected as a key. `processed + ignored + failed +
 * unprocessed` always equals `received`.
 */
final readonly class BatchCounters
{
    public function __construct(
        public int $received,
        public int $processed,
        public int $ignored,
        public int $failed,
        public int $unprocessed,
    ) {}

    /**
     * @param  array<string, mixed>  $body  The decoded 200 body.
     */
    public static function fromResponseBody(array $body): self
    {
        $counters = is_array($body['items'] ?? null) ? $body['items'] : [];

        return new self(
            self::count($counters, 'received'),
            self::count($counters, 'processed'),
            self::count($counters, 'ignored'),
            self::count($counters, 'failed'),
            self::count($counters, 'unprocessed'),
        );
    }

    /**
     * Items the server rejected individually. Terminal by design: it would
     * reject them again, so re-sending would loop forever.
     */
    public function hasFailures(): bool
    {
        return $this->failed > 0;
    }

    /**
     * Items the server accepted but ran out of time to process. These come back
     * to the spool, named by their index in the batch that was sent.
     */
    public function hasUnprocessed(): bool
    {
        return $this->unprocessed > 0;
    }

    /**
     * @param  array<array-key, mixed>  $counters
     */
    private static function count(array $counters, string $key): int
    {
        $value = $counters[$key] ?? 0;

        return is_numeric($value) ? (int) $value : 0;
    }
}
