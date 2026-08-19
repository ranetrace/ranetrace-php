<?php

declare(strict_types=1);

use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\ItemByteBudget;

/**
 * The budget is the last thing that touches an item before the buffer, and the
 * only place the drop decision is made, so the policy is tested here in full.
 * The capture-path tests next door assert that each of the four handoffs runs
 * it, not that the policy is right.
 */
function itemBudget(string $directory): ItemByteBudget
{
    return new ItemByteBudget(new InternalLogger(testConfig([
        'buffer_path' => $directory,
        'internal_logging' => ['enabled' => true, 'level' => 'debug'],
    ])));
}

function budgetLogContents(string $directory): string
{
    $files = glob($directory.'/internal-*.log') ?: [];

    return implode('', array_map(static fn (string $file): string => (string) file_get_contents($file), $files));
}

/**
 * An item comfortably over the per-item budget, built from string fields that
 * are each over the per-field budget, so shrinking them can bring it back
 * inside.
 *
 * @return array<string, mixed>
 */
function shrinkableItem(): array
{
    return [
        'message' => str_repeat('m', 40_000),
        'stack' => str_repeat('s', 40_000),
        'channel' => 'app',
    ];
}

test('an item within the budget is returned byte for byte', function (): void {
    $directory = tempDirectory();
    $item = ['message' => 'Payment gateway timed out', 'context' => ['order' => 42]];

    expect(itemBudget($directory)->cap('logs', $item))->toBe($item)
        ->and(budgetLogContents($directory))->toBe('');
});

test('an oversize string field is cut to the field budget and marked with the truncation suffix', function (): void {
    $directory = tempDirectory();

    $item = itemBudget($directory)->cap('logs', shrinkableItem());

    expect($item)->not->toBeNull()
        ->and($item['message'])->toBe(str_repeat('m', ItemByteBudget::MAX_ITEM_FIELD_BYTES).'... (truncated)')
        ->and($item['stack'])->toBe(str_repeat('s', ItemByteBudget::MAX_ITEM_FIELD_BYTES).'... (truncated)')
        ->and(mb_strlen((string) json_encode($item), '8bit'))->toBeLessThanOrEqual(ItemByteBudget::MAX_ITEM_BYTES);
});

test('a shrunk item keeps its exact key set, because the API matches field sets strictly', function (): void {
    $item = itemBudget(tempDirectory())->cap('logs', shrinkableItem());

    expect(array_keys((array) $item))->toBe(['message', 'stack', 'channel']);
});

test('a field within the per-field budget is left alone when the item is shrunk', function (): void {
    $item = itemBudget(tempDirectory())->cap('logs', shrinkableItem());

    expect($item['channel'])->toBe('app');
});

test('an oversize array field is replaced wholesale rather than cut mid structure', function (): void {
    $item = itemBudget(tempDirectory())->cap('logs', [
        'message' => 'boom',
        'context' => ['blob' => str_repeat('c', 80_000)],
    ]);

    expect($item['context'])->toBe(['_truncated' => 'Field exceeded the per-item budget and was removed'])
        ->and(json_decode((string) json_encode($item), true))->toBeArray();
});

test('a shrunk item is recorded in the internal log', function (): void {
    $directory = tempDirectory();

    itemBudget($directory)->cap('logs', shrinkableItem());

    expect(budgetLogContents($directory))
        ->toContain('Captured item exceeded the per-item byte budget and was shrunk')
        ->toContain('"type":"logs"')
        ->toContain('"max_bytes":71680');
});

test('an irreducibly oversize item is dropped instead of buffered', function (): void {
    $directory = tempDirectory();

    // Twenty fields, each comfortably under the per-field budget, so nothing is
    // shrinkable and the item is still 100 KB after the pass.
    $item = [];

    for ($field = 0; $field < 20; $field++) {
        $item['field_'.$field] = str_repeat('x', 5_000);
    }

    expect(itemBudget($directory)->cap('errors', $item))->toBeNull()
        ->and(budgetLogContents($directory))
        ->toContain('Captured item exceeded the per-item byte budget and was dropped')
        ->toContain('"type":"errors"')
        ->not->toContain('was shrunk');
});

test('multibyte strings are measured and cut by bytes, and stay valid UTF-8', function (): void {
    // Ten thousand three-byte characters: 10,000 characters is within every
    // per-field character cap the capture paths apply, and 30,000 bytes is not.
    // This is the case a character cap cannot see and the byte budget can.
    $item = itemBudget(tempDirectory())->cap('logs', [
        'message' => str_repeat('→', 30_000),
        'stack' => str_repeat('→', 30_000),
    ]);

    expect(mb_check_encoding($item['message'], 'UTF-8'))->toBeTrue()
        ->and(mb_strlen($item['message'], '8bit'))->toBeLessThanOrEqual(ItemByteBudget::MAX_ITEM_FIELD_BYTES + 15)
        ->and(json_encode($item))->not->toBeFalse();
});
