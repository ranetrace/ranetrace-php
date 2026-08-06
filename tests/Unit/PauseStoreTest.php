<?php

declare(strict_types=1);

use Ranetrace\Php\Buffer\PauseStore;

function pauseStore(string $directory, array $overrides = []): PauseStore
{
    return new PauseStore(testConfig(array_replace_recursive(['buffer_path' => $directory], $overrides)));
}

it('is not paused when nothing has ever been written', function (): void {
    $store = pauseStore(tempDirectory());

    expect($store->isGloballyPaused())->toBeFalse()
        ->and($store->isFeaturePaused('errors'))->toBeFalse()
        ->and($store->globalPause())->toBeNull()
        ->and($store->featurePause('errors'))->toBeNull();
});

it('records a global pause with its expiry and reason', function (): void {
    $directory = tempDirectory();
    $store = pauseStore($directory);

    $store->pauseGlobal(900, '401');

    expect($store->isGloballyPaused())->toBeTrue()
        ->and($store->globalPause()['reason'])->toBe('401')
        ->and(strtotime($store->globalPause()['paused_until']))->toBeGreaterThan(time() + 890)
        ->and(is_file($directory.'/pauses.json'))->toBeTrue();
});

it('keeps a global pause separate from the features', function (): void {
    $store = pauseStore(tempDirectory());

    $store->pauseGlobal(900, '401');

    expect($store->isFeaturePaused('errors'))->toBeFalse();
});

it('pauses one feature without touching the others', function (): void {
    $store = pauseStore(tempDirectory());

    $store->pauseFeature('errors', 900, '403');

    expect($store->isFeaturePaused('errors'))->toBeTrue()
        ->and($store->featurePause('errors')['reason'])->toBe('403')
        ->and($store->isFeaturePaused('events'))->toBeFalse()
        ->and($store->isGloballyPaused())->toBeFalse();
});

it('shares pauses between instances through the file', function (): void {
    $directory = tempDirectory();

    pauseStore($directory)->pauseFeature('logs', 900, '429');

    expect(pauseStore($directory)->isFeaturePaused('logs'))->toBeTrue();
});

it('prunes an expired pause on read', function (): void {
    $directory = tempDirectory();

    file_put_contents($directory.'/pauses.json', (string) json_encode([
        'global' => ['paused_until' => date('c', time() - 60), 'reason' => '401'],
        'features' => [
            'errors' => ['paused_until' => date('c', time() - 60), 'reason' => '429'],
            'events' => ['paused_until' => date('c', time() + 600), 'reason' => '403'],
        ],
    ]));

    $store = pauseStore($directory);

    expect($store->isGloballyPaused())->toBeFalse()
        ->and($store->isFeaturePaused('errors'))->toBeFalse()
        ->and($store->isFeaturePaused('events'))->toBeTrue();

    $persisted = json_decode((string) file_get_contents($directory.'/pauses.json'), true);

    expect($persisted['global'])->toBeNull()
        ->and(array_keys($persisted['features']))->toBe(['events']);
});

it('treats an unparseable expiry as expired rather than permanent', function (): void {
    $directory = tempDirectory();

    file_put_contents($directory.'/pauses.json', (string) json_encode([
        'global' => ['paused_until' => 'not a date', 'reason' => '401'],
        'features' => [],
    ]));

    expect(pauseStore($directory)->isGloballyPaused())->toBeFalse();
});

it('ignores a corrupt pause file instead of failing', function (): void {
    $directory = tempDirectory();
    file_put_contents($directory.'/pauses.json', 'not json');

    $store = pauseStore($directory);

    expect($store->isGloballyPaused())->toBeFalse();

    $store->pauseFeature('errors', 900, '500');

    expect($store->isFeaturePaused('errors'))->toBeTrue();
});

it('clears a global pause', function (): void {
    $store = pauseStore(tempDirectory());
    $store->pauseGlobal(900, '401');

    $store->clearGlobalPause();

    expect($store->isGloballyPaused())->toBeFalse();
});

it('clears one feature pause and leaves the rest', function (): void {
    $store = pauseStore(tempDirectory());
    $store->pauseFeature('errors', 900, '403');
    $store->pauseFeature('events', 900, '429');

    $store->clearFeaturePause('errors');

    expect($store->isFeaturePaused('errors'))->toBeFalse()
        ->and($store->isFeaturePaused('events'))->toBeTrue();
});

it('gives a zero second pause at least one second so it is observable', function (): void {
    $directory = tempDirectory();
    $store = pauseStore($directory);

    $before = time();
    $store->pauseFeature('errors', 0, '429');

    // Assert on the raw stored expiry rather than isFeaturePaused() or the
    // pruning accessors: a one-second pause can genuinely expire between write
    // and check on a loaded parallel test run, which made those flaky.
    $data = json_decode((string) file_get_contents($directory.'/pauses.json'), true);

    expect(strtotime($data['features']['errors']['paused_until']))->toBeGreaterThanOrEqual($before + 1);
});

it('creates the buffer directory for the pause file', function (): void {
    $directory = tempDirectory().'/nested/pauses';

    pauseStore($directory)->pauseGlobal(900, '401');

    expect(is_file($directory.'/pauses.json'))->toBeTrue();
});

it('does not throw when the lock is held elsewhere', function (): void {
    $directory = tempDirectory();
    $store = pauseStore($directory, ['batch' => ['lock_wait' => 0]]);

    $contender = fopen($directory.'/pauses.lock', 'c');
    flock($contender, LOCK_EX);

    try {
        $store->pauseGlobal(900, '401');

        expect($store->isGloballyPaused())->toBeFalse();
    } finally {
        flock($contender, LOCK_UN);
        fclose($contender);
    }
});
