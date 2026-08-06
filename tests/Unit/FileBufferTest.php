<?php

declare(strict_types=1);

use Ranetrace\Php\Buffer\FileBuffer;
use Ranetrace\Php\Support\InternalLogger;

function fileBuffer(string $directory, array $overrides = []): FileBuffer
{
    $config = testConfig(array_replace_recursive([
        'buffer_path' => $directory,
        'internal_logging' => ['enabled' => true, 'level' => 'debug'],
    ], $overrides));

    return new FileBuffer($config, new InternalLogger($config));
}

function internalLogContents(string $directory): string
{
    $files = glob($directory.'/internal-*.log') ?: [];

    return implode('', array_map(static fn (string $file): string => (string) file_get_contents($file), $files));
}

it('lists the four buffer types it spools', function (): void {
    expect(fileBuffer(tempDirectory())->types())->toBe(['errors', 'events', 'logs', 'javascript_errors']);
});

it('creates the buffer directory on demand', function (): void {
    $directory = tempDirectory().'/nested/buffer';

    expect(fileBuffer($directory)->addItem('errors', ['message' => 'boom']))->toBeTrue()
        ->and(is_dir($directory))->toBeTrue()
        ->and(is_file($directory.'/errors.json'))->toBeTrue();
});

it('wraps each payload in an id, data and timestamp envelope', function (): void {
    $buffer = fileBuffer(tempDirectory());
    $buffer->addItem('errors', ['message' => 'boom']);

    $taken = $buffer->take('errors', 10);

    expect($taken)->toHaveCount(1)
        ->and(array_keys($taken[0]))->toBe(['id', 'data', 'timestamp'])
        ->and($taken[0]['data'])->toBe(['message' => 'boom'])
        ->and($taken[0]['timestamp'])->toBeInt()
        ->and($taken[0]['id'])->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/');
});

it('gives every envelope its own id', function (): void {
    $buffer = fileBuffer(tempDirectory());
    $buffer->addItems('events', [['event_name' => 'a'], ['event_name' => 'b']]);

    $ids = array_column($buffer->take('events', 10), 'id');

    expect($ids)->toHaveCount(2)->and($ids[0])->not->toBe($ids[1]);
});

it('drains in arrival order and removes what it hands out', function (): void {
    $buffer = fileBuffer(tempDirectory());
    $buffer->addItems('logs', [['message' => 'one'], ['message' => 'two'], ['message' => 'three']]);

    $first = $buffer->take('logs', 2);

    expect(array_column($first, 'data'))->toBe([['message' => 'one'], ['message' => 'two']])
        ->and($buffer->count('logs'))->toBe(1)
        ->and(array_column($buffer->take('logs', 10), 'data'))->toBe([['message' => 'three']])
        ->and($buffer->count('logs'))->toBe(0);
});

it('survives a fresh instance reading what another wrote', function (): void {
    $directory = tempDirectory();

    fileBuffer($directory)->addItem('errors', ['message' => 'persisted']);

    expect(fileBuffer($directory)->count('errors'))->toBe(1);
});

it('removes the buffer file once it is fully drained', function (): void {
    $directory = tempDirectory();
    $buffer = fileBuffer($directory);
    $buffer->addItem('errors', ['message' => 'boom']);
    $buffer->take('errors', 10);

    expect(is_file($directory.'/errors.json'))->toBeFalse();
});

it('reports the oldest buffered timestamp', function (): void {
    $buffer = fileBuffer(tempDirectory());

    expect($buffer->oldestTimestamp('errors'))->toBeNull();

    $buffer->addItem('errors', ['message' => 'boom']);

    expect($buffer->oldestTimestamp('errors'))->toBeInt();
});

it('treats an empty add as a success without touching disk', function (): void {
    $directory = tempDirectory();

    expect(fileBuffer($directory)->addItems('errors', []))->toBeTrue()
        ->and(is_file($directory.'/errors.json'))->toBeFalse();
});

it('rejects an unknown buffer type instead of writing an unvalidated path', function (): void {
    $directory = tempDirectory();
    $buffer = fileBuffer($directory);

    expect($buffer->addItem('../escape', ['message' => 'boom']))->toBeFalse()
        ->and($buffer->take('../escape', 10))->toBe([])
        ->and($buffer->count('../escape'))->toBe(0)
        ->and(glob($directory.'/*.json'))->toBe([]);
});

it('drops the oldest items when the buffer overflows', function (): void {
    $buffer = fileBuffer(tempDirectory(), ['batch' => ['max_buffer_size' => 3]]);

    $buffer->addItems('errors', [
        ['message' => 'one'],
        ['message' => 'two'],
        ['message' => 'three'],
        ['message' => 'four'],
        ['message' => 'five'],
    ]);

    expect(array_column($buffer->take('errors', 10), 'data'))->toBe([
        ['message' => 'three'],
        ['message' => 'four'],
        ['message' => 'five'],
    ]);
});

it('logs an overflow once per cycle and again after a drain reopens it', function (): void {
    $directory = tempDirectory();
    $buffer = fileBuffer($directory, ['batch' => ['max_buffer_size' => 2]]);

    $buffer->addItems('errors', [['message' => 'one'], ['message' => 'two'], ['message' => 'three']]);
    $buffer->addItems('errors', [['message' => 'four']]);

    expect(mb_substr_count(internalLogContents($directory), 'Ranetrace buffer overflow'))->toBe(1)
        ->and(is_file($directory.'/errors.overflow'))->toBeTrue();

    $buffer->take('errors', 10);

    expect(is_file($directory.'/errors.overflow'))->toBeFalse();

    $buffer->addItems('errors', [['message' => 'five'], ['message' => 'six'], ['message' => 'seven']]);

    expect(mb_substr_count(internalLogContents($directory), 'Ranetrace buffer overflow'))->toBe(2);
});

it('records the dropped count and the cap in the overflow log', function (): void {
    $directory = tempDirectory();

    fileBuffer($directory, ['batch' => ['max_buffer_size' => 2]])
        ->addItems('errors', [['message' => 'one'], ['message' => 'two'], ['message' => 'three'], ['message' => 'four']]);

    expect(internalLogContents($directory))->toContain('"type":"errors","dropped":2,"max":2');
});

it('discards a buffer that has been idle past its ttl', function (): void {
    $directory = tempDirectory();
    $buffer = fileBuffer($directory, ['batch' => ['buffer_ttl' => 60]]);
    $buffer->addItem('errors', ['message' => 'stale']);

    touch($directory.'/errors.json', time() - 120);
    clearstatcache();

    expect($buffer->count('errors'))->toBe(0)
        ->and(is_file($directory.'/errors.json'))->toBeFalse();
});

it('keeps a buffer that is still within its ttl', function (): void {
    $directory = tempDirectory();
    $buffer = fileBuffer($directory, ['batch' => ['buffer_ttl' => 3600]]);
    $buffer->addItem('errors', ['message' => 'fresh']);

    touch($directory.'/errors.json', time() - 120);
    clearstatcache();

    expect($buffer->count('errors'))->toBe(1);
});

it('refreshes the ttl on every write', function (): void {
    $directory = tempDirectory();
    $buffer = fileBuffer($directory, ['batch' => ['buffer_ttl' => 60]]);
    $buffer->addItem('errors', ['message' => 'first']);

    touch($directory.'/errors.json', time() - 30);
    clearstatcache();

    $buffer->addItem('errors', ['message' => 'second']);
    clearstatcache();

    expect(filemtime($directory.'/errors.json'))->toBeGreaterThan(time() - 5)
        ->and($buffer->count('errors'))->toBe(2);
});

it('discards an unreadable buffer file rather than choking on it', function (): void {
    $directory = tempDirectory();
    $buffer = fileBuffer($directory);
    $buffer->addItem('errors', ['message' => 'boom']);

    file_put_contents($directory.'/errors.json', 'not json');

    expect($buffer->count('errors'))->toBe(0)
        ->and(internalLogContents($directory))->toContain('Buffer file was unreadable');
});

it('returns false from addItems when the lock is held elsewhere', function (): void {
    $directory = tempDirectory();
    $buffer = fileBuffer($directory, ['batch' => ['lock_wait' => 0]]);
    $buffer->addItem('errors', ['message' => 'first']);

    $contender = fopen($directory.'/errors.lock', 'c');
    flock($contender, LOCK_EX);

    try {
        expect($buffer->addItem('errors', ['message' => 'blocked']))->toBeFalse()
            ->and($buffer->take('errors', 10))->toBe([]);
    } finally {
        flock($contender, LOCK_UN);
        fclose($contender);
    }

    expect(internalLogContents($directory))->toContain('Could not acquire buffer lock to add items')
        ->and($buffer->count('errors'))->toBe(1);
});

it('waits for a contended lock up to the configured window', function (): void {
    $directory = tempDirectory();
    $buffer = fileBuffer($directory, ['batch' => ['lock_wait' => 1]]);

    $contender = fopen($directory.'/errors.lock', 'c');
    flock($contender, LOCK_EX);

    $started = microtime(true);
    $result = $buffer->addItem('errors', ['message' => 'blocked']);
    $elapsed = microtime(true) - $started;

    flock($contender, LOCK_UN);
    fclose($contender);

    expect($result)->toBeFalse()->and($elapsed)->toBeGreaterThanOrEqual(1.0);
});

it('leaves items in place when the remainder cannot be persisted', function (): void {
    $directory = tempDirectory();
    // The internal log lives in the same directory, so it cannot be written
    // either; without this the fallback would print to stderr and Pest would
    // flag the test as risky.
    $buffer = fileBuffer($directory, ['internal_logging' => ['stderr_fallback' => false]]);
    $buffer->addItems('errors', [['message' => 'one'], ['message' => 'two']]);

    chmod($directory, 0500);

    try {
        expect($buffer->take('errors', 1))->toBe([]);
    } finally {
        chmod($directory, 0700);
    }

    expect($buffer->count('errors'))->toBe(2);
})->skip(fn (): bool => function_exists('posix_getuid') && posix_getuid() === 0, 'root ignores directory permissions');

it('clears a type on request', function (): void {
    $directory = tempDirectory();
    $buffer = fileBuffer($directory);
    $buffer->addItem('errors', ['message' => 'boom']);

    $buffer->clear('errors');

    expect($buffer->count('errors'))->toBe(0);
});
