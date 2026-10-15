<?php

declare(strict_types=1);

use Ranetrace\Php\Errors\ErrorItemShedder;
use Ranetrace\Php\Errors\FrameCap;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\ItemByteBudget;

/**
 * How an over-budget error item gives up its frame fields: sources first, then
 * frames from the middle, then previous exceptions, and never a `_truncated`
 * marker inside `frames` or `previous`, which the backend refuses.
 */

/**
 * @return array<string, mixed>
 */
function shedFrame(int $index, int $fill = 0, bool $withSource = false): array
{
    return [
        'index' => $index,
        'file' => 'app/Service.php',
        'line' => 10,
        'class' => null,
        'function' => 'handle'.str_repeat('→', $fill),
        'type' => null,
        'is_vendor' => false,
        'source' => $withSource ? ['start_line' => 5, 'lines' => [str_repeat('s', 1_000)]] : null,
    ];
}

/**
 * @param  list<array<string, mixed>>  $frames
 * @return array<string, mixed>
 */
function shedPrevious(array $frames, bool $withSource = false, string $message = 'inner'): array
{
    return [
        'type' => 'LogicException',
        'message' => $message,
        'file' => 'app/Service.php',
        'line' => 4,
        'source' => $withSource ? ['start_line' => 1, 'lines' => [str_repeat('t', 1_000)]] : null,
        'frames' => $frames,
        'frames_omitted' => 0,
    ];
}

/**
 * @param  list<array<string, mixed>>  $frames
 * @param  list<array<string, mixed>>|null  $previous
 * @return array<string, mixed>
 */
function shedItem(array $frames, ?array $previous, string $message = 'boom'): array
{
    return [
        'message' => $message,
        'file' => 'app/Service.php',
        'line' => 12,
        'type' => 'RuntimeException',
        'frames' => $frames,
        'frames_omitted' => 0,
        'previous' => $previous,
    ];
}

function shedBytes(mixed $value): int
{
    return mb_strlen((string) json_encode($value), '8bit');
}

test('an item within budget is returned untouched', function (): void {
    $item = shedItem([shedFrame(0, 0, true)], [shedPrevious([shedFrame(0, 0, true)], true)]);

    expect(ErrorItemShedder::shed($item, shedBytes($item)))->toBe($item);
});

/**
 * Every source is the same size, so a budget n sources below the item's size
 * sheds exactly the first n in the order: the previous exceptions' frames
 * (farthest exception first, outermost frame first), the item's own frames
 * outermost first, its first app frame, then the throw sites, farthest first.
 */
test('sources are shed in order, the first app frame and the throw sites last', function (int $shed): void {
    $item = shedItem(
        array_map(static fn (int $index): array => shedFrame($index, 0, $index !== 1), range(0, 4)),
        [
            shedPrevious([shedFrame(0, 0, true), shedFrame(1, 0, true)], true),
            shedPrevious([shedFrame(0, 0, true), shedFrame(1, 0, true)], true),
        ],
    );

    $order = [
        ['previous', 1, 'frames', 1], ['previous', 1, 'frames', 0],
        ['previous', 0, 'frames', 1], ['previous', 0, 'frames', 0],
        ['frames', 4], ['frames', 3], ['frames', 2],
        ['frames', 0],
        ['previous', 1], ['previous', 0],
    ];

    $saving = shedBytes(['start_line' => 5, 'lines' => [str_repeat('s', 1_000)]]) - 4;
    $shedItem = ErrorItemShedder::shed($item, shedBytes($item) - ($shed - 1) * $saving - 1);

    foreach ($order as $position => $path) {
        $owner = $shedItem;

        foreach ($path as $segment) {
            $owner = $owner[$segment];
        }

        expect($owner['source'] === null)->toBe($position < $shed, 'source at '.implode('.', $path));
    }

    expect(array_column($shedItem['frames'], 'index'))->toBe(range(0, 4))
        ->and($shedItem['previous'])->toHaveCount(2);
})->with(range(1, 10));

test('with every source gone, frame lists shrink from the middle, the previous lists first', function (): void {
    $frames = static fn (): array => array_map(static fn (int $index): array => shedFrame($index, 100), range(0, 49));
    $item = shedItem($frames(), [shedPrevious($frames()), shedPrevious($frames())]);
    $item['previous'][1]['frames_omitted'] = 7;

    $frameBytes = shedBytes(shedFrame(0, 100)) + 1;
    $budget = shedBytes($item) - 50 * $frameBytes - 20 * $frameBytes;

    $shedItem = ErrorItemShedder::shed($item, $budget);
    $near = $shedItem['previous'][0];
    $kept = count($near['frames']);

    expect($shedItem['previous'][1]['frames'])->toBe([])
        ->and($shedItem['previous'][1]['frames_omitted'])->toBe(57)
        ->and($kept)->toBeLessThan(50)->toBeGreaterThan(20)
        ->and($near['frames_omitted'])->toBe(50 - $kept)
        ->and(array_column($near['frames'], 'index'))->toBe(FrameCap::positions(50, $kept))
        ->and($shedItem['frames'])->toHaveCount(50)
        ->and($shedItem['frames_omitted'])->toBe(0)
        ->and(shedBytes($shedItem))->toBeLessThanOrEqual($budget);
});

test('the item own frames shrink last, keeping both ends', function (): void {
    $item = shedItem(array_map(static fn (int $index): array => shedFrame($index, 100), range(0, 49)), null);
    $item['frames_omitted'] = 30;

    $shedItem = ErrorItemShedder::shed($item, intdiv(shedBytes($item), 2));
    $kept = count($shedItem['frames']);

    expect(array_column($shedItem['frames'], 'index'))->toBe(FrameCap::positions(50, $kept))
        ->and($shedItem['frames_omitted'])->toBe(30 + 50 - $kept)
        ->and($kept)->toBeGreaterThan(0)->toBeLessThan(50);
});

test('previous exceptions are dropped from the far end once every frame is gone', function (): void {
    $previous = [
        shedPrevious([shedFrame(0)], false, 'nearest '.str_repeat('a', 5_000)),
        shedPrevious([shedFrame(0)], false, 'middle '.str_repeat('b', 5_000)),
        shedPrevious([shedFrame(0)], false, 'farthest '.str_repeat('c', 5_000)),
    ];
    $item = shedItem([shedFrame(0)], $previous);

    $oneLeft = ErrorItemShedder::shed($item, 7_000);
    $noneLeft = ErrorItemShedder::shed($item, 1_000);

    expect($oneLeft['previous'])->toHaveCount(1)
        ->and($oneLeft['previous'][0]['message'])->toStartWith('nearest ')
        ->and($oneLeft['previous'][0]['frames'])->toBe([])
        ->and($oneLeft['frames'])->toBe([])
        ->and($oneLeft['frames_omitted'])->toBe(1)
        ->and($noneLeft['previous'])->toBeNull();
});

test('an error item over budget for other reasons never gets the truncation marker inside its frame fields', function (): void {
    $directory = tempDirectory();
    $budget = new ItemByteBudget(new InternalLogger(testConfig([
        'buffer_path' => $directory,
        'internal_logging' => ['enabled' => false],
    ])));

    $frames = array_map(static fn (int $index): array => shedFrame($index, 50, true), range(0, 49));
    $item = shedItem($frames, [shedPrevious($frames, true)], str_repeat('m', 100_000));

    $capped = $budget->cap('errors', $item);

    expect($capped)->not->toBeNull()
        ->and($capped['frames'])->toBe([])
        ->and($capped['frames_omitted'])->toBe(50)
        ->and($capped['previous'])->toBeNull()
        ->and($capped['message'])->toEndWith('... (truncated)')
        ->and((string) json_encode($capped))->not->toContain('_truncated')
        ->and(shedBytes($capped))->toBeLessThanOrEqual(ItemByteBudget::MAX_ITEM_BYTES);
});

test('a real error item whose sources overflow the budget keeps its frames, its first app frame and its throw sites', function (): void {
    $root = frameProject();
    $deep = deepRecursionException($root, 80, str_repeat('p', 400));
    $exception = new RuntimeException('wrapper', 0, $deep);

    $item = framePayload(frameBuilder($root), $exception);

    expect(shedBytes($item))->toBeGreaterThan(ItemByteBudget::MAX_ITEM_BYTES);

    $capped = (new ItemByteBudget(new InternalLogger(testConfig(['buffer_path' => $root, 'internal_logging' => ['enabled' => false]]))))
        ->cap('errors', $item);

    $previousSources = array_map(static fn (array $frame): bool => $frame['source'] !== null, $capped['previous'][0]['frames']);
    $kept = count(array_filter($previousSources));
    $firstOwnAppFrame = array_values(array_filter($item['frames'], static fn (array $frame): bool => $frame['source'] !== null))[0];

    expect($capped)->not->toBeNull()
        ->and(shedBytes($capped))->toBeLessThanOrEqual(ItemByteBudget::MAX_ITEM_BYTES)
        ->and((string) json_encode($capped))->not->toContain('_truncated')
        ->and($capped['frames'])->toHaveCount(count($item['frames']))
        ->and($capped['previous'][0]['frames'])->toHaveCount(50)
        ->and($capped['previous'][0]['source'])->toBe($item['previous'][0]['source'])
        ->and($capped['frames'][array_search($firstOwnAppFrame['index'], array_column($capped['frames'], 'index'), true)]['source'])->toBe($firstOwnAppFrame['source'])
        ->and(array_slice($previousSources, 0, $kept))->toBe(array_fill(0, $kept, true))
        ->and($kept)->toBeLessThan(count(array_filter(array_column($item['previous'][0]['frames'], 'source'))));
});
