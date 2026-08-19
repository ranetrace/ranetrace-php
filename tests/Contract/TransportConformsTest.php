<?php

declare(strict_types=1);

use Ranetrace\Php\Contract\WireContract;
use Ranetrace\Php\Http\ApiClient;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\ItemByteBudget;
use Ranetrace\Php\Tests\Doubles\FakeHttpClient;
use Ranetrace\Php\Worker\Worker;

/**
 * The worker's transport table and its budgets are private, which is right for
 * the class and awkward for a conformance check. Reflection is the honest way
 * to read them: widening their visibility so a test can see them would make an
 * internal decision part of the package's public surface.
 */
function contractWorkerConstant(string $name): mixed
{
    return (new ReflectionClass(Worker::class))->getConstant($name);
}

test('the worker posts each type to the path and wrapper the contract names', function (): void {
    $endpoints = contractWorkerConstant('ENDPOINTS');
    $contract = WireContract::endpoints()['endpoints'];
    $wrappers = WireContract::envelope()['wrappers'];

    expect(array_keys($endpoints))->toEqualCanonicalizing(WireContract::itemTypes());

    foreach ($endpoints as $type => $endpoint) {
        expect($endpoint['path'])->toBe($contract[$type]['path'])
            ->and($endpoint['wrapper'])->toBe($contract[$type]['wrapper'])
            ->and($endpoint['wrapper'])->toBe($wrappers[$type]);
    }
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

test('the worker pause lengths equal the response contract', function (): void {
    $responses = WireContract::responses();

    expect(contractWorkerConstant('PAUSE_SECONDS'))->toBe($responses['pause_seconds_default'])
        ->and(contractWorkerConstant('RATE_LIMIT_FLOOR_SECONDS'))->toBe($responses['rate_limit_floor_seconds'])
        ->and($responses['statuses']['429']['pause_seconds_floor'])->toBe($responses['rate_limit_floor_seconds']);

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
