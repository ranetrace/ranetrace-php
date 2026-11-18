<?php

declare(strict_types=1);

use Composer\InstalledVersions;
use Ranetrace\Php\Buffer\PauseStore;
use Ranetrace\Php\Config;
use Ranetrace\Php\Events\EventTracker;
use Ranetrace\Php\Http\ApiClient;
use Ranetrace\Php\Http\RawResponse;
use Ranetrace\Php\JavaScript\Relay;
use Ranetrace\Php\Support\FingerprintGenerator;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;
use Ranetrace\Php\Tests\Doubles\ArrayBuffer;
use Ranetrace\Php\Tests\Doubles\FakeHttpClient;
use Ranetrace\Php\Worker\Worker;

/**
 * A worker wired to an in-memory buffer and a fake transport, plus the pieces a
 * test needs to assert on.
 *
 * @return array{worker: Worker, buffer: ArrayBuffer, pauses: PauseStore, http: FakeHttpClient, config: Config, directory: string}
 */
function workerHarness(FakeHttpClient $http, array $overrides = []): array
{
    $directory = tempDirectory();

    $config = testConfig(array_replace_recursive([
        'buffer_path' => $directory,
        'internal_logging' => ['enabled' => false],
    ], $overrides));

    $buffer = new ArrayBuffer;
    $pauses = new PauseStore($config);
    $log = new InternalLogger($config);

    return [
        'worker' => new Worker($config, $buffer, $pauses, new ApiClient($config, $http, $log), $log),
        'buffer' => $buffer,
        'pauses' => $pauses,
        'http' => $http,
        'config' => $config,
        'directory' => $directory,
    ];
}

function seedBuffer(ArrayBuffer $buffer, string $type, int $count): void
{
    for ($index = 0; $index < $count; $index++) {
        $buffer->addItem($type, ['message' => 'item-'.$index]);
    }
}

it('sends a batch to the right endpoint with the right agent and wrapper key', function (string $type, string $path, string $agent): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    seedBuffer($harness['buffer'], $type, 1);

    $harness['worker']->run($type);

    expect($harness['http']->requests[0]['url'])->toBe('https://api.ranetrace.com/v1'.$path)
        ->and($harness['http']->requests[0]['headers']['User-Agent'])->toBe($agent)
        ->and(array_keys($harness['http']->payload()))->toBe([$type]);
})->with([
    ['errors', '/errors/store', 'Ranetrace-PHP/Errors/1.0'],
    ['events', '/events/store', 'Ranetrace-PHP/Events/1.0'],
    ['logs', '/logs/store', 'Ranetrace-PHP/Logs/1.0'],
    ['javascript_errors', '/javascript-errors/store', 'Ranetrace-PHP/JavaScriptErrors/1.0'],
]);

it('sends payloads on the drain\'s wire without touching the buffer, the pauses or the last-batch stamp', function (int $status): void {
    $harness = workerHarness(FakeHttpClient::respondingWith($status));
    seedBuffer($harness['buffer'], 'events', 1);

    $result = $harness['worker']->send('events', [['event_name' => 'test_event']]);

    expect($result['status'])->toBe($status)
        ->and($harness['http']->requests[0]['url'])->toBe('https://api.ranetrace.com/v1/events/store')
        ->and($harness['http']->requests[0]['headers']['User-Agent'])->toBe('Ranetrace-PHP/Events/1.0')
        ->and($harness['http']->requests[0]['timeout'])->toBe(10)
        ->and($harness['http']->payload())->toBe(['events' => [['event_name' => 'test_event']]])
        ->and($harness['buffer']->payloads('events'))->toBe([['message' => 'item-0']])
        ->and(is_file($harness['directory'].'/pauses.json'))->toBeFalse()
        ->and($harness['worker']->lastBatchAt('events'))->toBeNull();
})->with([200, 401, 500]);

it('reads the logs timeout from the logging config section', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200), ['logging' => ['timeout' => 42]]);
    seedBuffer($harness['buffer'], 'logs', 1);

    $harness['worker']->run('logs');

    expect($harness['http']->requests[0]['timeout'])->toBe(42);
});

it('drains every type when none is named', function (): void {
    $harness = workerHarness(new FakeHttpClient(
        new RawResponse(200, '{}'),
        new RawResponse(200, '{}'),
    ));
    seedBuffer($harness['buffer'], 'errors', 1);
    seedBuffer($harness['buffer'], 'events', 1);

    $harness['worker']->run();

    expect($harness['http']->requests)->toHaveCount(2)
        ->and($harness['buffer']->count('errors'))->toBe(0)
        ->and($harness['buffer']->count('events'))->toBe(0);
});

it('skips a type with an empty buffer', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));

    $harness['worker']->run();

    expect($harness['http']->requests)->toBe([]);
});

it('ignores a run for an unknown type', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    seedBuffer($harness['buffer'], 'errors', 1);

    $harness['worker']->run('page_visits');

    expect($harness['http']->requests)->toBe([])
        ->and($harness['buffer']->count('errors'))->toBe(1);
});

it('sends nothing at all while globally paused', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    seedBuffer($harness['buffer'], 'errors', 1);
    $harness['pauses']->pauseGlobal(900, '401');

    $harness['worker']->run();

    expect($harness['http']->requests)->toBe([])
        ->and($harness['buffer']->count('errors'))->toBe(1);
});

it('skips a paused feature but still drains the others', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    seedBuffer($harness['buffer'], 'errors', 1);
    seedBuffer($harness['buffer'], 'events', 1);
    $harness['pauses']->pauseFeature('errors', 900, '429');

    $harness['worker']->run();

    expect($harness['http']->requests)->toHaveCount(1)
        ->and(array_keys($harness['http']->payload()))->toBe(['events'])
        ->and($harness['buffer']->count('errors'))->toBe(1);
});

it('takes at most a thousand items in one run', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    seedBuffer($harness['buffer'], 'errors', 1005);

    $harness['worker']->run('errors');

    expect($harness['http']->payload()['errors'])->toHaveCount(Worker::MAX_ITEMS_PER_RUN)
        ->and($harness['buffer']->count('errors'))->toBe(5);
});

it('stamps the last successful batch', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    seedBuffer($harness['buffer'], 'errors', 1);

    $harness['worker']->run('errors');

    expect($harness['worker']->lastBatchAt('errors'))->toBeInt()
        ->and($harness['worker']->lastBatchAt('events'))->toBeNull()
        ->and(is_file($harness['directory'].'/state.json'))->toBeTrue();
});

it('keeps nothing after a clean success', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200, ['items' => ['received' => 2, 'processed' => 2, 'failed' => 0, 'unprocessed' => 0]]));
    seedBuffer($harness['buffer'], 'errors', 2);

    $harness['worker']->run('errors');

    expect($harness['buffer']->count('errors'))->toBe(0)
        ->and($harness['pauses']->isFeaturePaused('errors'))->toBeFalse();
});

it('treats failed items as terminal and does not re-buffer them', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200, ['items' => ['received' => 2, 'processed' => 1, 'failed' => 1]]));
    seedBuffer($harness['buffer'], 'errors', 2);

    $harness['worker']->run('errors');

    expect($harness['buffer']->count('errors'))->toBe(0);
});

it('re-buffers only the items the server reported as unprocessed', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200, [
        'items' => ['received' => 4, 'processed' => 2, 'unprocessed' => 2],
        'unprocessed_indexes' => [1, 3],
    ]));
    seedBuffer($harness['buffer'], 'errors', 4);

    $harness['worker']->run('errors');

    expect($harness['buffer']->payloads('errors'))->toBe([
        ['message' => 'item-1'],
        ['message' => 'item-3'],
    ]);
});

it('ignores an unprocessed index that is out of range', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200, [
        'items' => ['unprocessed' => 2],
        'unprocessed_indexes' => [0, 99],
    ]));
    seedBuffer($harness['buffer'], 'errors', 2);

    $harness['worker']->run('errors');

    expect($harness['buffer']->payloads('errors'))->toBe([['message' => 'item-0']]);
});

it('re-buffers everything and pauses the feature on a network failure', function (): void {
    $harness = workerHarness(new FakeHttpClient(RawResponse::transportFailure('Connection refused')));
    seedBuffer($harness['buffer'], 'errors', 3);

    $harness['worker']->run('errors');

    expect($harness['buffer']->count('errors'))->toBe(3)
        ->and($harness['pauses']->featurePause('errors')['reason'])->toBe('network')
        ->and($harness['pauses']->isGloballyPaused())->toBeFalse();
});

it('pauses globally on a rejected api key', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(401, ['error' => ['message' => 'Invalid API key']]));
    seedBuffer($harness['buffer'], 'errors', 2);

    $harness['worker']->run('errors');

    expect($harness['pauses']->isGloballyPaused())->toBeTrue()
        ->and($harness['pauses']->globalPause()['reason'])->toBe('401')
        ->and($harness['buffer']->count('errors'))->toBe(2);
});

it('stops touching the other types once a 401 pauses everything', function (): void {
    $harness = workerHarness(new FakeHttpClient(new RawResponse(401, '{}')));
    seedBuffer($harness['buffer'], 'errors', 1);
    seedBuffer($harness['buffer'], 'events', 1);

    $harness['worker']->run();

    expect($harness['http']->requests)->toHaveCount(1)
        ->and($harness['buffer']->count('events'))->toBe(1);
});

it('re-buffers and pauses the feature on a forbidden response', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(403, ['error' => ['message' => 'Forbidden']]));
    seedBuffer($harness['buffer'], 'errors', 2);

    $harness['worker']->run('errors');

    expect($harness['buffer']->count('errors'))->toBe(2)
        ->and($harness['pauses']->featurePause('errors')['reason'])->toBe('403')
        ->and($harness['pauses']->isGloballyPaused())->toBeFalse();
});

it('drops the batch and pauses the feature on a payload too large', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(413, ['error' => ['message' => 'Payload Too Large']]));
    seedBuffer($harness['buffer'], 'errors', 2);

    $harness['worker']->run('errors');

    expect($harness['buffer']->count('errors'))->toBe(0)
        ->and($harness['pauses']->featurePause('errors')['reason'])->toBe('413');
});

it('drops the batch and pauses the feature on a validation failure', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(422, ['error' => ['message' => 'Validation failed']]));
    seedBuffer($harness['buffer'], 'errors', 2);

    $harness['worker']->run('errors');

    expect($harness['buffer']->count('errors'))->toBe(0)
        ->and($harness['pauses']->featurePause('errors')['reason'])->toBe('422');
});

it('honours a retry-after header when rate limited', function (): void {
    $harness = workerHarness(new FakeHttpClient(new RawResponse(429, '{}', ['retry-after' => '300'])));
    seedBuffer($harness['buffer'], 'errors', 2);

    $harness['worker']->run('errors');

    expect($harness['buffer']->count('errors'))->toBe(2)
        ->and($harness['pauses']->featurePause('errors')['reason'])->toBe('429')
        ->and(strtotime($harness['pauses']->featurePause('errors')['paused_until']))->toBeGreaterThan(time() + 290);
});

it('floors a missing retry-after at sixty seconds', function (): void {
    $harness = workerHarness(new FakeHttpClient(new RawResponse(429, '{}')));
    seedBuffer($harness['buffer'], 'errors', 1);

    $harness['worker']->run('errors');

    $pausedUntil = strtotime($harness['pauses']->featurePause('errors')['paused_until']);

    expect($pausedUntil)->toBeGreaterThan(time() + 50)
        ->and($pausedUntil)->toBeLessThanOrEqual(time() + 61);
});

it('floors a zero retry-after at sixty seconds', function (): void {
    $harness = workerHarness(new FakeHttpClient(new RawResponse(429, '{}', ['retry-after' => '0'])));
    seedBuffer($harness['buffer'], 'errors', 1);

    $harness['worker']->run('errors');

    expect(strtotime($harness['pauses']->featurePause('errors')['paused_until']))->toBeGreaterThan(time() + 50);
});

it('re-buffers and pauses the feature on a server error', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(500));
    seedBuffer($harness['buffer'], 'errors', 2);

    $harness['worker']->run('errors');

    expect($harness['buffer']->count('errors'))->toBe(2)
        ->and($harness['pauses']->featurePause('errors')['reason'])->toBe('500');
});

it('treats an unexpected status as transient', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(418));
    seedBuffer($harness['buffer'], 'errors', 2);

    $harness['worker']->run('errors');

    expect($harness['buffer']->count('errors'))->toBe(2)
        ->and($harness['pauses']->featurePause('errors')['reason'])->toBe('418');
});

it('does not stamp a last batch for a failed send', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(500));
    seedBuffer($harness['buffer'], 'errors', 1);

    $harness['worker']->run('errors');

    expect($harness['worker']->lastBatchAt('errors'))->toBeNull();
});

it('trims an oversize batch to the byte budget and re-buffers the tail', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));

    // Three items of ~2MB each: the first two fit inside the 4.5MB budget, the
    // third pushes past it and is deferred to the next run.
    foreach (['a', 'b', 'c'] as $marker) {
        $harness['buffer']->addItem('errors', ['message' => $marker, 'blob' => str_repeat($marker, 2_000_000)]);
    }

    $harness['worker']->run('errors');

    expect($harness['http']->payload()['errors'])->toHaveCount(2)
        ->and($harness['buffer']->payloads('errors'))->toHaveCount(1)
        ->and($harness['buffer']->payloads('errors')[0]['message'])->toBe('c');
});

it('always sends at least one item even when it alone exceeds the budget', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    $harness['buffer']->addItem('errors', ['blob' => str_repeat('x', 5_000_000)]);
    $harness['buffer']->addItem('errors', ['message' => 'next']);

    $harness['worker']->run('errors');

    expect($harness['http']->payload()['errors'])->toHaveCount(1)
        ->and($harness['buffer']->payloads('errors'))->toBe([['message' => 'next']]);
});

/**
 * Envelopes as an earlier capture left them: fixed ids, an old capture time.
 *
 * @param  list<array<string, mixed>>  $payloads
 * @return list<array{id: string, data: array<string, mixed>, timestamp: int}>
 */
function seedEnvelopes(ArrayBuffer $buffer, string $type, array $payloads): array
{
    $envelopes = [];

    foreach ($payloads as $index => $data) {
        $envelopes[] = ['id' => 'envelope-'.$index, 'data' => $data, 'timestamp' => time() - 3600 + $index];
    }

    $buffer->items[$type] = $envelopes;

    return $envelopes;
}

/**
 * The API tells a batch sent again from a second capture by the item's own id,
 * so the id on the wire has to be the one made at capture, on every attempt.
 */
it('sends a captured item again with the id it was captured with', function (string $type, array $capture): void {
    $harness = workerHarness(new FakeHttpClient(
        new RawResponse(500, '{"success":false}'),
        new RawResponse(200, '{"success":true}'),
    ), ['javascript_errors' => ['enabled' => true]]);

    $capture[0]($harness['config'], $harness['buffer']);

    $captured = $harness['buffer']->payloads($type)[0]['id'];

    $harness['worker']->run($type);
    $harness['pauses']->clearFeaturePause($type);
    $harness['worker']->run($type);

    expect($harness['http']->requests)->toHaveCount(2)
        ->and($harness['http']->payload(0)[$type][0]['id'])->toBe($captured)
        ->and($harness['http']->payload(1)[$type][0]['id'])->toBe($captured)
        ->and($harness['buffer']->count($type))->toBe(0);
})->with([
    'an event' => ['events', [static function (Config $config, ArrayBuffer $buffer): void {
        $log = new InternalLogger($config);

        (new EventTracker($config, $buffer, new SecretScrubber($config, $log), new FingerprintGenerator($config), $log))
            ->track('order_shipped');
    }]],
    'a javascript error' => ['javascript_errors', [static function (Config $config, ArrayBuffer $buffer): void {
        $log = new InternalLogger($config);

        (new Relay($config, $buffer, new SecretScrubber($config, $log), new FingerprintGenerator($config), $log))->handleRequest(
            ['HTTP_HOST' => 'app.test', 'HTTP_ORIGIN' => 'https://app.test', 'HTTP_USER_AGENT' => 'Test Browser'],
            ['message' => 'boom', 'url' => 'https://app.test/cart', 'timestamp' => '2026-08-06T10:00:00+00:00'],
        );
    }]],
]);

it('puts a failed batch back with its ids and capture times', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(500));
    $envelopes = seedEnvelopes($harness['buffer'], 'errors', [['message' => 'one'], ['message' => 'two']]);

    $harness['worker']->run('errors');

    expect($harness['buffer']->items['errors'])->toBe($envelopes);
});

it('puts the unprocessed items back with their envelopes, in batch order', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200, [
        'items' => ['received' => 4, 'processed' => 2, 'unprocessed' => 2],
        'unprocessed_indexes' => [3, 1],
    ]));
    $envelopes = seedEnvelopes($harness['buffer'], 'errors', [
        ['message' => 'zero'], ['message' => 'one'], ['message' => 'two'], ['message' => 'three'],
    ]);

    $harness['worker']->run('errors');

    expect($harness['buffer']->items['errors'])->toBe([$envelopes[1], $envelopes[3]]);
});

it('puts the items deferred by the byte budget back with their envelopes', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    $envelopes = seedEnvelopes($harness['buffer'], 'errors', array_map(
        static fn (string $marker): array => ['message' => $marker, 'blob' => str_repeat($marker, 2_000_000)],
        ['a', 'b', 'c'],
    ));

    $harness['worker']->run('errors');

    expect($harness['buffer']->items['errors'])->toBe([$envelopes[2]]);
});

it('puts a failed batch back ahead of the items deferred from it', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(500));
    $envelopes = seedEnvelopes($harness['buffer'], 'errors', array_map(
        static fn (string $marker): array => ['message' => $marker, 'blob' => str_repeat($marker, 2_000_000)],
        ['a', 'b', 'c'],
    ));

    $harness['worker']->run('errors');

    expect($harness['buffer']->items['errors'])->toBe($envelopes);
});

/**
 * A process without the key cannot speak for one that has it, and the pause
 * store is shared by both: a pause set here would hold the keyed web process
 * back for fifteen minutes over a key it does have.
 */
it('takes nothing, sends nothing and pauses nothing without an api key', function (string $key, ?string $type): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200), ['key' => $key]);
    $envelopes = seedEnvelopes($harness['buffer'], 'errors', [['message' => 'one'], ['message' => 'two']]);

    $harness['worker']->run($type);

    expect($harness['http']->requests)->toBe([])
        ->and($harness['buffer']->items['errors'])->toBe($envelopes)
        ->and($harness['pauses']->featurePause('errors'))->toBeNull()
        ->and($harness['pauses']->globalPause())->toBeNull()
        ->and(is_file($harness['directory'].'/pauses.json'))->toBeFalse()
        ->and($harness['worker']->lastBatchAt('errors'))->toBeNull();
})->with([
    'an empty key' => [''],
    'a space' => [' '],
    'tabs and newlines' => ["\t\n "],
])->with([
    'every type' => [null],
    'the named type' => ['errors'],
]);

it('leaves the pauses it finds as they are without an api key', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200), ['key' => '']);
    seedBuffer($harness['buffer'], 'errors', 1);
    seedBuffer($harness['buffer'], 'events', 1);
    $harness['pauses']->pauseGlobal(900, '401');
    $harness['pauses']->pauseFeature('events', 300, '429');
    $before = (string) file_get_contents($harness['directory'].'/pauses.json');

    $harness['worker']->run();

    expect($harness['http']->requests)->toBe([])
        ->and($harness['buffer']->count('errors'))->toBe(1)
        ->and($harness['buffer']->count('events'))->toBe(1)
        ->and((string) file_get_contents($harness['directory'].'/pauses.json'))->toBe($before);
});

it('logs one warning naming the waiting types when a run has no api key', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200), [
        'key' => '',
        'internal_logging' => ['enabled' => true, 'level' => 'debug'],
    ]);
    seedBuffer($harness['buffer'], 'errors', 2);
    seedBuffer($harness['buffer'], 'logs', 1);

    $harness['worker']->run();

    $log = internalLogContents($harness['directory']);

    expect(mb_substr_count($log, "\n"))->toBe(1)
        ->and($log)->toContain('ranetrace_internal.WARNING: Skipping run, no API key is configured {"types":["errors","logs"]}');
});

/**
 * A keyless development site flushes on the shutdown of every request, nearly
 * always with an empty buffer, and must not get a log line per request.
 */
it('logs nothing when a run without an api key finds nothing waiting', function (?string $type): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200), [
        'key' => '',
        'internal_logging' => ['enabled' => true, 'level' => 'debug'],
    ]);
    seedBuffer($harness['buffer'], 'events', 1);
    $harness['buffer']->take('events', 1);

    $harness['worker']->run($type);

    expect(internalLogContents($harness['directory']))->toBe('');
})->with([
    'every type' => [null],
    'the named type' => ['errors'],
]);

it('drains normally on a keyed run after a keyless one', function (): void {
    $keyless = workerHarness(FakeHttpClient::respondingWith(200), ['key' => '']);
    seedBuffer($keyless['buffer'], 'errors', 1);
    seedBuffer($keyless['buffer'], 'events', 1);

    $keyless['worker']->run();

    $config = testConfig(['buffer_path' => $keyless['directory'], 'internal_logging' => ['enabled' => false]]);
    $http = new FakeHttpClient(new RawResponse(200, '{}'), new RawResponse(200, '{}'));
    $log = new InternalLogger($config);
    $pauses = new PauseStore($config);

    new Worker($config, $keyless['buffer'], $pauses, new ApiClient($config, $http, $log), $log)->run();

    expect($http->requests)->toHaveCount(2)
        ->and($keyless['buffer']->count('errors'))->toBe(0)
        ->and($keyless['buffer']->count('events'))->toBe(0)
        ->and($pauses->featurePause('errors'))->toBeNull()
        ->and($pauses->globalPause())->toBeNull();
});

it('never throws when the buffer refuses to take items back', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(500));
    seedBuffer($harness['buffer'], 'errors', 1);
    $harness['buffer']->rejectWrites = true;

    $harness['worker']->run('errors');

    expect($harness['pauses']->featurePause('errors')['reason'])->toBe('500');
});

/**
 * @return array{worker: Worker, buffer: ArrayBuffer, pauses: PauseStore, http: FakeHttpClient, config: Config, directory: string}
 */
function loggingWorkerHarness(FakeHttpClient $http): array
{
    return workerHarness($http, ['internal_logging' => ['enabled' => true, 'level' => 'debug']]);
}

it('drops an item it cannot encode from the batch and sends the rest, never measuring it as zero bytes', function (): void {
    $harness = loggingWorkerHarness(FakeHttpClient::respondingWith(200));
    $harness['buffer']->addItem('logs', ['message' => 'before']);
    $harness['buffer']->addItem('logs', ['message' => 'poison', 'context' => ['ratio' => INF]]);
    $harness['buffer']->addItem('logs', ['message' => 'after']);

    $harness['worker']->run('logs');

    expect($harness['http']->requests)->toHaveCount(1)
        ->and(array_column($harness['http']->payload()['logs'], 'message'))->toBe(['before', 'after'])
        ->and($harness['buffer']->count('logs'))->toBe(0)
        ->and($harness['pauses']->featurePause('logs'))->toBeNull()
        ->and(internalLogContents($harness['directory']))
        ->toContain('Dropped items that could not be encoded as JSON')
        ->toContain('"type":"logs"')
        ->toContain('"dropped":1');
});

it('sends nothing and pauses nothing when every item in the batch cannot be encoded', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    $harness['buffer']->addItem('events', ['properties' => ['average' => NAN]]);
    $harness['buffer']->addItem('events', ['properties' => ['trend' => -INF]]);

    $harness['worker']->run('events');

    expect($harness['http']->requests)->toBe([])
        ->and($harness['buffer']->count('events'))->toBe(0)
        ->and($harness['pauses']->featurePause('events'))->toBeNull();
});

it('keeps at least one encodable item when an unencodable one comes first', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    $harness['buffer']->addItem('errors', ['message' => 'poison', 'line' => NAN]);
    $harness['buffer']->addItem('errors', ['message' => 'big', 'blob' => str_repeat('x', 5_000_000)]);
    $harness['buffer']->addItem('errors', ['message' => 'next']);

    $harness['worker']->run('errors');

    expect(array_column($harness['http']->payload()['errors'], 'message'))->toBe(['big'])
        ->and($harness['buffer']->payloads('errors'))->toBe([['message' => 'next']]);
});

/**
 * A stamp in the state file, as an earlier run would have left it.
 *
 * @param  array<string, int>  $state
 */
function seedWorkerState(string $directory, array $state): void
{
    file_put_contents($directory.'/state.json', (string) json_encode($state));
}

it('sends one heartbeat with the sdk and its version when the buffer is empty and none was sent before', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));

    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toHaveCount(1)
        ->and($harness['http']->requests[0]['url'])->toBe('https://api.ranetrace.com/v1/heartbeat')
        ->and($harness['http']->requests[0]['headers']['User-Agent'])->toBe('Ranetrace-PHP/Heartbeat/1.0')
        ->and($harness['http']->payload())->toBe([
            'sdk' => 'php',
            'sdk_version' => InstalledVersions::getPrettyVersion('ranetrace/ranetrace-php'),
        ]);
});

it('sends no second heartbeat within five minutes of the first', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));

    $harness['worker']->heartbeat();
    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toHaveCount(1);
});

it('sends a heartbeat or holds it by the age of the last one', function (int $age, int $expected): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    seedWorkerState($harness['directory'], ['heartbeat' => time() - $age]);

    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toHaveCount($expected);
})->with([
    'four minutes old' => [240, 0],
    'five minutes old' => [300, 1],
    'an hour old' => [3600, 1],
]);

/**
 * A server whose clock was set back would otherwise be silent until the clock
 * caught up with the stamp, and the API would call it stopped.
 */
it('sends a heartbeat when the last one is stamped in the future', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    seedWorkerState($harness['directory'], ['heartbeat' => time() + 86400]);

    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toHaveCount(1)
        ->and($harness['worker']->lastHeartbeatAt())->toBeLessThanOrEqual(time());
});

it('sends no heartbeat without an api key', function (string $key): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200), [
        'key' => $key,
        'internal_logging' => ['enabled' => true, 'level' => 'debug'],
    ]);

    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toBe([])
        ->and($harness['worker']->lastHeartbeatAt())->toBeNull()
        ->and(internalLogContents($harness['directory']))->toBe('');
})->with([
    'no key' => [''],
    'a key of whitespace' => ["  \t"],
]);

it('sends no heartbeat while the master switch is off', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200), ['enabled' => false]);

    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toBe([])
        ->and($harness['worker']->lastHeartbeatAt())->toBeNull();
});

it('sends no heartbeat while everything is paused', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    $harness['pauses']->pauseGlobal(900, '401');

    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toBe([])
        ->and($harness['worker']->lastHeartbeatAt())->toBeNull();
});

/**
 * The order a cron run has: the drain meets the rejected key, and the
 * heartbeat after it stays silent, so the API sees the application stop.
 */
it('sends no heartbeat after a drain that met a rejected key', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(401, ['error' => ['message' => 'Invalid API key']]));
    seedBuffer($harness['buffer'], 'errors', 1);

    $harness['worker']->run();
    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toHaveCount(1)
        ->and($harness['http']->requests[0]['url'])->toBe('https://api.ranetrace.com/v1/errors/store');
});

it('still sends a heartbeat while one feature is paused', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    $harness['pauses']->pauseFeature('errors', 900, '403');

    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toHaveCount(1);
});

it('still sends a heartbeat when every feature is switched off', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200), [
        'errors' => ['enabled' => false],
        'events' => ['enabled' => false],
    ]);

    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toHaveCount(1);
});

it('never sends a heartbeat from a drain', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    seedBuffer($harness['buffer'], 'errors', 1);

    $harness['worker']->run();
    $harness['worker']->run();

    expect($harness['http']->requests)->toHaveCount(1)
        ->and($harness['http']->requests[0]['url'])->toBe('https://api.ranetrace.com/v1/errors/store')
        ->and($harness['worker']->lastHeartbeatAt())->toBeNull();
});

it('sets no pause and leaves the buffer alone whatever a heartbeat is answered', function (FakeHttpClient $http): void {
    $harness = workerHarness($http);
    seedBuffer($harness['buffer'], 'errors', 2);
    $before = $harness['buffer']->items;

    $harness['worker']->heartbeat();

    expect($http->requests)->toHaveCount(1)
        ->and($harness['buffer']->items)->toBe($before)
        ->and($harness['pauses']->globalPause())->toBeNull()
        ->and($harness['pauses']->featurePause('errors'))->toBeNull()
        ->and(is_file($harness['directory'].'/pauses.json'))->toBeFalse();
})->with([
    'a server error' => [fn (): FakeHttpClient => FakeHttpClient::respondingWith(500, ['success' => false, 'error' => ['message' => 'Server error']])],
    'a network failure' => [fn (): FakeHttpClient => new FakeHttpClient(RawResponse::transportFailure('Could not resolve host'))],
    'a rejected key' => [fn (): FakeHttpClient => FakeHttpClient::respondingWith(401, ['success' => false, 'error' => ['message' => 'Unauthenticated']])],
    'the throttle' => [fn (): FakeHttpClient => FakeHttpClient::respondingWith(429, ['success' => false, 'error' => ['message' => 'Too many requests']], ['retry-after' => '30'])],
    'a refused body' => [fn (): FakeHttpClient => FakeHttpClient::respondingWith(422, ['success' => false, 'error' => ['message' => 'The sdk field is required.']])],
]);

it('lifts no pause on a heartbeat the api accepts', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    $harness['pauses']->pauseFeature('errors', 900, '403');

    $harness['worker']->heartbeat();

    expect($harness['pauses']->featurePause('errors')['reason'])->toBe('403');
});

it('does not send a failed heartbeat again before the next interval', function (): void {
    $harness = workerHarness(new FakeHttpClient(
        new RawResponse(500, '{"success":false}'),
        new RawResponse(200, '{"success":true}'),
    ));

    $harness['worker']->heartbeat();
    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toHaveCount(1);
});

it('writes one line to the internal log for a heartbeat that failed', function (FakeHttpClient $http, string $line): void {
    $harness = loggingWorkerHarness($http);

    $harness['worker']->heartbeat();

    $log = internalLogContents($harness['directory']);

    expect(mb_substr_count($log, "\n"))->toBe(1)
        ->and($log)->toContain($line);
})->with([
    'a server error' => [
        fn (): FakeHttpClient => FakeHttpClient::respondingWith(500, ['success' => false, 'error' => ['message' => 'Server error']]),
        'ranetrace_internal.WARNING: Heartbeat was not accepted {"status":500,"message":"Server error"}',
    ],
    'a network failure' => [
        fn (): FakeHttpClient => new FakeHttpClient(RawResponse::transportFailure('Could not resolve host')),
        'ranetrace_internal.WARNING: Heartbeat was not accepted {"status":0,"message":"Could not resolve host"}',
    ],
    'an error body with no message' => [
        fn (): FakeHttpClient => FakeHttpClient::respondingWith(503, 'Service Unavailable'),
        'ranetrace_internal.WARNING: Heartbeat was not accepted {"status":503,"message":"No message"}',
    ],
]);

it('writes one debug line for a heartbeat the api accepted', function (): void {
    $harness = loggingWorkerHarness(FakeHttpClient::respondingWith(200));

    $harness['worker']->heartbeat();

    $log = internalLogContents($harness['directory']);

    expect(mb_substr_count($log, "\n"))->toBe(1)
        ->and($log)->toContain('ranetrace_internal.DEBUG: Heartbeat sent {"status":200}');
});

it('never throws when the transport throws on a heartbeat', function (): void {
    $http = new class extends FakeHttpClient
    {
        public function post(string $url, array $headers, string $body, int $connectTimeout, int $timeout): RawResponse
        {
            throw new RuntimeException('transport exploded');
        }
    };
    $harness = workerHarness($http);

    $harness['worker']->heartbeat();

    expect($harness['pauses']->globalPause())->toBeNull()
        ->and($harness['worker']->lastHeartbeatAt())->toBeInt();
});

it('keeps the last batch stamps when it stamps a heartbeat, and the heartbeat stamp when it stamps a batch', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    seedWorkerState($harness['directory'], ['errors' => 1_700_000_000]);

    $harness['worker']->heartbeat();
    $heartbeat = $harness['worker']->lastHeartbeatAt();
    seedBuffer($harness['buffer'], 'events', 1);
    $harness['worker']->run('events');

    expect($harness['worker']->lastBatchAt('errors'))->toBe(1_700_000_000)
        ->and($harness['worker']->lastBatchAt('events'))->toBeInt()
        ->and($heartbeat)->toBeInt()
        ->and($harness['worker']->lastHeartbeatAt())->toBe($heartbeat);
});

it('reads a state file that is not json as no heartbeat sent', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200));
    file_put_contents($harness['directory'].'/state.json', '{"heartbeat": 17');

    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toHaveCount(1)
        ->and($harness['worker']->lastHeartbeatAt())->toBeInt();
});

/**
 * Without the stamp nothing would hold the next run back, and a cron job
 * every minute would send a heartbeat every minute.
 */
it('sends no heartbeat when its time cannot be written, and says so in the internal log', function (): void {
    $harness = loggingWorkerHarness(FakeHttpClient::respondingWith(200));
    // The log file exists before the directory is closed, so the line can land.
    new InternalLogger($harness['config'])->debug('before');
    chmod($harness['directory'], 0550);

    try {
        $harness['worker']->heartbeat();
    } finally {
        chmod($harness['directory'], 0700);
    }

    expect($harness['http']->requests)->toBe([])
        ->and(internalLogContents($harness['directory']))
        ->toContain('ranetrace_internal.WARNING: Heartbeat not sent, its time could not be written to the state file');
})->skip(runsAsRoot(...), 'root ignores file modes');

/**
 * A new install whose cron job runs before anything was captured: the buffer
 * directory is not there yet, and the application is quiet, not stopped.
 */
it('sends a heartbeat and keeps its time when the buffer directory does not exist yet', function (): void {
    $directory = tempDirectory().'/not-created-yet';
    $harness = workerHarness(FakeHttpClient::respondingWith(200), ['buffer_path' => $directory]);

    $harness['worker']->heartbeat();
    $harness['worker']->heartbeat();

    expect($harness['http']->requests)->toHaveCount(1)
        ->and(json_decode((string) file_get_contents($directory.'/state.json'), true))->toHaveKey('heartbeat');
});
