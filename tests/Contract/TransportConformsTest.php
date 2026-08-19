<?php

declare(strict_types=1);

use Ranetrace\Php\Contract\WireContract;
use Ranetrace\Php\Http\ApiClient;
use Ranetrace\Php\Http\EndpointTable;
use Ranetrace\Php\Http\PauseScope;
use Ranetrace\Php\Http\ResponsePolicy;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\ItemByteBudget;
use Ranetrace\Php\Tests\Doubles\FakeHttpClient;
use Ranetrace\Php\Worker\Worker;

/**
 * The worker's batch budgets are private, which is right for the class and
 * awkward for a conformance check. Reflection is the honest way to read them:
 * widening their visibility so a test can see them would make an internal
 * decision part of the package's public surface.
 */
function contractWorkerConstant(string $name): mixed
{
    return (new ReflectionClass(Worker::class))->getConstant($name);
}

test('the endpoint table names the path and wrapper the contract does', function (): void {
    $table = EndpointTable::contract();
    $contract = WireContract::endpoints()['endpoints'];
    $wrappers = WireContract::envelope()['wrappers'];

    expect($table->types())->toEqualCanonicalizing(WireContract::itemTypes());

    foreach ($table->all() as $type => $endpoint) {
        expect($endpoint->path)->toBe($contract[$type]['path'])
            ->and($endpoint->wrapper)->toBe($contract[$type]['wrapper'])
            ->and($endpoint->wrapper)->toBe($wrappers[$type]);
    }
});

/**
 * The SDK name is deliberately absent from the table: it is per SDK, not per
 * endpoint, and `ranetrace/ranetrace-laravel` reads this same table to build
 * `Ranetrace-Laravel/...`. The fixture's format string is what both fill in.
 */
test('the endpoint table builds the contracted User-Agent for whichever SDK asks', function (): void {
    $contract = WireContract::headers();
    $table = EndpointTable::contract();

    foreach ($table->all() as $endpoint) {
        expect($endpoint->userAgent('PHP'))->toBe(str_replace(
            ['{SDK}', '{Feature}', '{version}'],
            ['PHP', $endpoint->feature, $contract['api_version']],
            $contract['request']['User-Agent']['format'],
        ))->and($endpoint->userAgent('Laravel'))->toStartWith('Ranetrace-Laravel/');
    }

    expect($contract['request']['User-Agent']['examples'])
        ->toContain($table->get('errors')->userAgent('PHP'))
        ->toContain($table->get('javascript_errors')->userAgent('PHP'));
});

/**
 * The response matrix, row by row, read straight off the fixture. Both SDKs
 * decide through this one policy, so a drift between them now has to start as a
 * drift from the fixture and this test is where it stops.
 */
test('the response policy decides every contracted status the way the fixture states', function (string $status): void {
    $responses = WireContract::responses();
    $row = $responses['statuses'][$status];

    $outcome = (new ResponsePolicy)->decide([
        'status' => match ($status) {
            'network' => 0,
            'default' => 503,
            default => (int) $status,
        },
        'data' => [],
        'headers' => ['retry-after' => ''],
    ]);

    expect($outcome->pauseScope->value)->toBe($row['pause_scope'] ?? 'none')
        ->and($outcome->drop)->toBe($row['drop'])
        ->and($outcome->rebuffer)->toBe($row['rebuffer'] === true);

    // The 429 row states no fixed length: it reads the response instead, and
    // the substitute below is asserted separately.
    if ($row['pause_seconds'] !== null) {
        expect($outcome->pauseSeconds)->toBe($row['pause_seconds'])
            ->and($row['pause_seconds'])->toBe($responses['pause_seconds_default']);
    }
})->with(['401', '403', '413', '422', '429', 'default', 'network']);

test('the response policy substitutes the contracted floor for an absent Retry-After', function (mixed $header, ?int $expected): void {
    $responses = WireContract::responses();
    $floor = $responses['rate_limit_floor_seconds'];

    expect(ResponsePolicy::RATE_LIMIT_FLOOR_SECONDS)->toBe($floor)
        ->and(ResponsePolicy::PAUSE_SECONDS)->toBe($responses['pause_seconds_default'])
        ->and($responses['statuses']['429']['pause_seconds_floor'])->toBe($floor);

    $outcome = (new ResponsePolicy)->decide([
        'status' => 429,
        'data' => [],
        'headers' => ['retry-after' => $header],
    ]);

    expect($outcome->pauseSeconds)->toBe($expected ?? $floor);
})->with([
    'the endpoint named a pause length' => ['120', 120],
    // A missing header is stored as '' and casts to zero, which is the whole
    // reason the substitute exists.
    'the endpoint sent no Retry-After' => ['', null],
    'the endpoint sent a zero Retry-After' => ['0', null],
    // Not a lower bound: a small positive value is honoured as sent.
    'the endpoint named a short pause' => ['5', 5],
]);

test('the response policy reads the 200 counters and unprocessed indexes the contract describes', function (): void {
    $shape = WireContract::responses()['success_body']['shape'];

    $outcome = (new ResponsePolicy)->decide([
        'status' => 200,
        'data' => [
            'success' => true,
            'items' => ['received' => 4, 'processed' => 2, 'failed' => 1, 'unprocessed' => 1],
            'unprocessed_indexes' => [3],
        ],
        'headers' => ['retry-after' => ''],
    ]);

    expect(array_keys($shape['items']))->toEqualCanonicalizing(['received', 'processed', 'ignored', 'failed', 'unprocessed'])
        ->and($outcome->stampLastBatch)->toBeTrue()
        ->and($outcome->pauseScope)->toBe(PauseScope::None)
        ->and($outcome->rebuffer)->toBeFalse()
        // Absent counters read as zero rather than as a missing key.
        ->and($outcome->counters?->ignored)->toBe(0)
        ->and($outcome->counters?->hasFailures())->toBeTrue()
        ->and($outcome->unprocessedIndexes)->toBe([3])
        ->and($outcome->unprocessedPayloads([
            3 => ['id' => 'd', 'data' => ['message' => 'fourth'], 'timestamp' => 0],
        ]))->toBe([['message' => 'fourth']]);
});

test('the worker batch budgets equal the envelope contract', function (): void {
    $envelope = WireContract::envelope();

    expect(Worker::MAX_ITEMS_PER_RUN)->toBe($envelope['max_items_per_batch'])
        ->and(contractWorkerConstant('MAX_BATCH_BYTES'))->toBe($envelope['client_trim_bytes'])
        ->and($envelope['client_trim_bytes'])->toBeLessThan($envelope['server_max_body_bytes']);
});

test('the capture item budget equals the envelope contract', function (): void {
    $policy = WireContract::envelope()['client_item_policy'];

    expect(ItemByteBudget::MAX_ITEM_BYTES)->toBe($policy['max_item_bytes'])
        ->and(ItemByteBudget::MAX_ITEM_FIELD_BYTES)->toBe($policy['max_item_field_bytes'])
        ->and($policy['max_item_field_bytes'])->toBeLessThan($policy['max_item_bytes'])
        // The drop-rather-than-mark half of the policy is the part no constant
        // can express, so the contract states it and this pins the statement.
        ->and($policy['never_send_marker_key'])->toBeTrue();
});

test('an item the budget dropped is never replaced with a marker payload', function (): void {
    $budget = new ItemByteBudget(new InternalLogger(testConfig([
        'buffer_path' => tempDirectory(),
        'internal_logging' => ['enabled' => false],
    ])));

    $item = [];

    for ($field = 0; $field < 20; $field++) {
        $item['field_'.$field] = str_repeat('x', 5_000);
    }

    // Null, not an item carrying `_truncated` or any other stand-in key: the
    // errors endpoint matches field sets strictly, so a marker key would take
    // the whole batch of up to a thousand items down with it.
    expect($budget->cap('errors', $item))->toBeNull();
});

test('every fixed-length pause the contract names is the same default length', function (): void {
    $responses = WireContract::responses();

    foreach (['401', '403', '413', '422', 'default', 'network'] as $status) {
        expect($responses['statuses'][$status]['pause_seconds'])->toBe($responses['pause_seconds_default']);
    }
});

test('the api client sends exactly the contracted headers', function (): void {
    $config = testConfig(['buffer_path' => tempDirectory(), 'internal_logging' => ['enabled' => false]]);
    $http = FakeHttpClient::respondingWith(200);

    (new ApiClient($config, $http, new InternalLogger($config)))
        ->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, [['message' => 'boom']]);

    $contract = WireContract::headers();
    $sent = $http->requests[0]['headers'];

    expect(array_keys($sent))->toEqualCanonicalizing(array_keys($contract['request']))
        ->and($sent['Content-Type'])->toBe($contract['request']['Content-Type']['value'])
        ->and($sent['Accept'])->toBe($contract['request']['Accept']['value'])
        ->and($sent['Ranetrace-API-Version'])->toBe($contract['request']['Ranetrace-API-Version']['value'])
        ->and($sent['Ranetrace-API-Version'])->toBe($contract['api_version'])
        ->and($sent['Authorization'])->toBe(str_replace('{api key}', 'test-api-key-12345', $contract['request']['Authorization']['format']))
        ->and($contract['request']['User-Agent']['examples'])->toContain($sent['User-Agent']);
});

test('the api client wraps a batch under the single contracted key', function (): void {
    $config = testConfig(['buffer_path' => tempDirectory(), 'internal_logging' => ['enabled' => false]]);
    $http = FakeHttpClient::respondingWith(200);
    $wrapper = WireContract::envelope()['wrappers']['javascript_errors'];

    (new ApiClient($config, $http, new InternalLogger($config)))->sendBatch(
        WireContract::endpoints()['endpoints']['javascript_errors']['path'],
        $wrapper,
        'Ranetrace-PHP/JavaScriptErrors/1.0',
        10,
        [WireContract::item('javascript_errors')['examples']['minimal']],
    );

    expect(array_keys($http->payload()))->toBe([$wrapper])
        ->and($http->payload()[$wrapper])->toHaveCount(1);
});
