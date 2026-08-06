<?php

declare(strict_types=1);

use Ranetrace\Php\Support\PayloadSizer;

test('it returns data within the budget untouched', function (): void {
    $data = ['order_id' => 42, 'items' => ['a', 'b']];

    expect(PayloadSizer::capBytes($data, 51_200, 'too big'))->toBe($data);
});

test('it replaces oversized data wholesale with the truncation marker', function (): void {
    $data = ['blob' => str_repeat('x', 200)];

    expect(PayloadSizer::capBytes($data, 100, 'Context exceeded 50KB limit and was removed'))
        ->toBe(['_truncated' => 'Context exceeded 50KB limit and was removed']);
});

test('it budgets the encoded byte size, which multibyte data inflates', function (): void {
    // 20 characters that each cost six bytes as a JSON escape sequence. The
    // budget is against what actually goes on the wire, not the value's length.
    $data = ['note' => str_repeat('é', 20)];

    expect(mb_strlen($data['note']))->toBe(20)
        ->and(mb_strlen((string) json_encode($data), '8bit'))->toBeGreaterThan(100)
        ->and(PayloadSizer::capBytes($data, 100, 'too big'))->toBe(['_truncated' => 'too big'])
        ->and(PayloadSizer::capBytes($data, 200, 'too big'))->toBe($data);
});

test('the boundary is exclusive: exactly the budget still passes', function (): void {
    $data = ['a' => 'bc'];
    $size = mb_strlen((string) json_encode($data), '8bit');

    expect(PayloadSizer::capBytes($data, $size, 'too big'))->toBe($data)
        ->and(PayloadSizer::capBytes($data, $size - 1, 'too big'))->toBe(['_truncated' => 'too big']);
});

test('an empty array fits any realistic budget', function (): void {
    // It still encodes to two bytes, so the marker wins below that.
    expect(PayloadSizer::capBytes([], 2, 'too big'))->toBe([])
        ->and(PayloadSizer::capBytes([], 1, 'too big'))->toBe(['_truncated' => 'too big']);
});
