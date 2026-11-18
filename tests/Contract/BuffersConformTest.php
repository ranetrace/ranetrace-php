<?php

declare(strict_types=1);

use Ranetrace\Php\Buffer\FileBuffer;
use Ranetrace\Php\Buffer\MemoryBuffer;
use Ranetrace\Php\Contract\WireContract;
use Ranetrace\Php\Support\InternalLogger;

/**
 * Each buffer keeps its own list of the types it spools, and the worker drains
 * whatever a buffer lists, so a type missing from a buffer is never sent.
 */
test('the memory buffer spools the item types the contract says this package sends', function (): void {
    expect((new MemoryBuffer)->types())->toBe(WireContract::itemTypes());
});

test('the file buffer spools the item types the contract says this package sends', function (): void {
    $config = testConfig(['buffer_path' => tempDirectory()]);

    expect((new FileBuffer($config, new InternalLogger($config)))->types())->toBe(WireContract::itemTypes());
});
