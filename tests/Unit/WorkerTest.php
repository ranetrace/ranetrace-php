<?php

declare(strict_types=1);

use Ranetrace\Php\Buffer\PauseStore;
use Ranetrace\Php\Config;
use Ranetrace\Php\Http\ApiClient;
use Ranetrace\Php\Http\RawResponse;
use Ranetrace\Php\Support\InternalLogger;
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

it('does not send when the api key is missing', function (): void {
    $harness = workerHarness(FakeHttpClient::respondingWith(200), ['key' => '']);
    seedBuffer($harness['buffer'], 'errors', 1);

    $harness['worker']->run('errors');

    expect($harness['http']->requests)->toBe([])
        ->and($harness['buffer']->count('errors'))->toBe(1)
        ->and($harness['pauses']->featurePause('errors')['reason'])->toBe('network');
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

function workerLogContents(string $directory): string
{
    $files = glob($directory.'/internal-*.log') ?: [];

    return implode('', array_map(static fn (string $file): string => (string) file_get_contents($file), $files));
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
        ->and(workerLogContents($harness['directory']))
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
