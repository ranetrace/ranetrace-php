<?php

declare(strict_types=1);

namespace Ranetrace\Php\Http;

/**
 * What one batch response means: do the items go back on the spool, does
 * anything pause and for how long, and are the items terminal.
 *
 * Produced by {@see ResponsePolicy} and consumed by both SDKs' transports. It
 * carries the decision only; how a host re-buffers, where it stores a pause and
 * what it writes to its diagnostics log stay the host's own business.
 */
final readonly class BatchOutcome
{
    /**
     * @param  int  $status  The HTTP status, or 0 for a failure that never reached one.
     * @param  bool  $rebuffer  Whether the whole batch goes back on the spool.
     * @param  bool  $drop  Whether the items are terminal. The inverse reading of $rebuffer for every non-200 row; on a 200 both are false and {@see $unprocessedIndexes} names what comes back.
     * @param  string  $reason  The pause reason to record, e.g. `network` or `422`.
     * @param  bool  $transient  Whether a host with a retry mechanism of its own may spend it before pausing. The file-based worker has nowhere to retry to and pauses on the spot; the Laravel job releases itself with backoff and pauses only once its envelope is exhausted. Both land on the same pause.
     * @param  bool  $stampLastBatch  Whether this response counts as a successful drain.
     * @param  list<int>  $unprocessedIndexes  Zero-based positions in the batch that was sent, for the items the server could not process.
     */
    public function __construct(
        public int $status,
        public bool $rebuffer,
        public bool $drop,
        public PauseScope $pauseScope,
        public ?int $pauseSeconds,
        public string $reason,
        public bool $transient,
        public bool $stampLastBatch = false,
        public ?BatchCounters $counters = null,
        public array $unprocessedIndexes = [],
    ) {}

    /**
     * Whether anything at all pauses on this response.
     */
    public function pauses(): bool
    {
        return $this->pauseScope !== PauseScope::None;
    }

    /**
     * The payloads of the items named by {@see $unprocessedIndexes}, in the
     * order the server named them.
     *
     * @param  array<int, array{id: string, data: array<string, mixed>, timestamp: int}>  $items  The batch as it was sent.
     * @return list<array<string, mixed>>
     */
    public function unprocessedPayloads(array $items): array
    {
        $payloads = [];

        foreach ($this->unprocessedIndexes as $index) {
            if (isset($items[$index])) {
                $payloads[] = $items[$index]['data'];
            }
        }

        return $payloads;
    }
}
