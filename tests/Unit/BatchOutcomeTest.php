<?php

declare(strict_types=1);

use Ranetrace\Php\Http\BatchOutcome;
use Ranetrace\Php\Http\PauseScope;

/**
 * @param  list<int>  $indexes
 */
function outcomeNaming(array $indexes): BatchOutcome
{
    return new BatchOutcome(
        status: 200,
        rebuffer: false,
        drop: false,
        pauseScope: PauseScope::None,
        pauseSeconds: null,
        reason: '',
        transient: false,
        stampLastBatch: true,
        unprocessedIndexes: $indexes,
    );
}

/**
 * @return list<array{id: string, data: array<string, mixed>, timestamp: int}>
 */
function sentBatch(): array
{
    return array_map(
        static fn (int $index): array => ['id' => 'item-'.$index, 'data' => ['message' => (string) $index], 'timestamp' => 1_700_000_000 + $index],
        range(0, 3),
    );
}

it('returns the whole envelopes the server named as unprocessed', function (): void {
    $batch = sentBatch();

    expect(outcomeNaming([1, 3])->unprocessedItems($batch))->toBe([$batch[1], $batch[3]]);
});

it('returns the unprocessed items in batch order, whatever order the server named them in', function (): void {
    $batch = sentBatch();

    expect(outcomeNaming([3, 0, 2])->unprocessedItems($batch))->toBe([$batch[0], $batch[2], $batch[3]]);
});

it('returns an item the server named twice only once', function (): void {
    $batch = sentBatch();

    expect(outcomeNaming([2, 2, 2])->unprocessedItems($batch))->toBe([$batch[2]]);
});

it('ignores an unprocessed index outside the batch', function (): void {
    $batch = sentBatch();

    expect(outcomeNaming([-1, 1, 4, 99])->unprocessedItems($batch))->toBe([$batch[1]]);
});

it('returns nothing when the server named nothing', function (): void {
    expect(outcomeNaming([])->unprocessedItems(sentBatch()))->toBe([]);
});
