<?php

declare(strict_types=1);

use Ranetrace\Php\Buffer\MemoryBuffer;

it('hands items back in the order they were added', function (): void {
    $buffer = new MemoryBuffer;
    $buffer->addItem('errors', ['message' => 'one']);
    $buffer->addItems('errors', [['message' => 'two'], ['message' => 'three']]);

    $taken = $buffer->take('errors', 2);

    expect(array_column($taken, 'data'))->toBe([['message' => 'one'], ['message' => 'two']])
        ->and($buffer->count('errors'))->toBe(1);
});

it('returns items to the head with their ids and capture times', function (): void {
    $buffer = new MemoryBuffer;
    $buffer->addItems('events', [['event_name' => 'one'], ['event_name' => 'two']]);
    $first = $buffer->take('events', 1);

    $buffer->returnItems('events', $first);
    $all = $buffer->take('events', 2);

    expect($all[0])->toBe($first[0])
        ->and($all[1]['data'])->toBe(['event_name' => 'two']);
});

it('refuses a type the sdk does not capture', function (): void {
    $buffer = new MemoryBuffer;

    expect($buffer->addItem('page_visits', ['url' => '/']))->toBeFalse()
        ->and($buffer->count('page_visits'))->toBe(0)
        ->and($buffer->types())->toBe(['errors', 'events', 'logs', 'javascript_errors']);
});

it('takes nothing for a limit below one', function (): void {
    $buffer = new MemoryBuffer;
    $buffer->addItem('logs', ['message' => 'kept']);

    expect($buffer->take('logs', 0))->toBe([])
        ->and($buffer->count('logs'))->toBe(1);
});
