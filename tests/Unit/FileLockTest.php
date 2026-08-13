<?php

declare(strict_types=1);

use Ranetrace\Php\Support\FileLock;

it('takes an uncontended lock and creates the sidecar file', function (): void {
    $directory = tempDirectory();
    $lock = new FileLock($directory.'/errors.lock', 0.0);

    $handle = $lock->acquire();

    expect($handle)->toBeResource()
        ->and(is_file($directory.'/errors.lock'))->toBeTrue();

    $lock->release($handle);
});

it('takes the lock again after it has been released', function (): void {
    $path = tempDirectory().'/errors.lock';
    $lock = new FileLock($path, 0.0);

    $first = $lock->acquire();
    $lock->release($first);

    $second = $lock->acquire();

    expect($second)->toBeResource();

    $lock->release($second);
});

it('gives up on a lock another process is holding', function (): void {
    $path = tempDirectory().'/errors.lock';
    $contender = fopen($path, 'c');
    flock($contender, LOCK_EX);

    try {
        expect((new FileLock($path, 0.0))->acquire())->toBeNull();
    } finally {
        flock($contender, LOCK_UN);
        fclose($contender);
    }
});

it('waits out the configured window before giving up on a contended lock', function (): void {
    $path = tempDirectory().'/errors.lock';
    $contender = fopen($path, 'c');
    flock($contender, LOCK_EX);

    try {
        $started = microtime(true);
        $handle = (new FileLock($path, 0.1))->acquire();
        $elapsed = microtime(true) - $started;

        // The wait is spelled as non-blocking retries because flock() has no
        // timeout, so the deadline is what bounds it, not the lock call.
        expect($handle)->toBeNull()
            ->and($elapsed)->toBeGreaterThanOrEqual(0.1);
    } finally {
        flock($contender, LOCK_UN);
        fclose($contender);
    }
});

it('returns null instead of throwing when the lock file cannot be opened', function (): void {
    $lock = new FileLock(tempDirectory().'/absent/errors.lock', 0.0);

    expect($lock->acquire())->toBeNull();
});
