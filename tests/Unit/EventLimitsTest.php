<?php

declare(strict_types=1);

use Ranetrace\Php\Events\EventLimits;
use Ranetrace\Php\Tests\Doubles\RecordingDiagnostics;

/**
 * An eight-key event item as {@see Ranetrace\Php\Events\EventItemBuilder}
 * makes it, written out so each test controls every byte.
 *
 * @param  array<array-key, mixed>  $properties
 * @return array<string, mixed>
 */
function limitedEvent(array $properties, ?string $url = null, string $name = 'checkout_completed'): array
{
    return [
        'id' => '5f0c2a9e-7d41-4b83-a6e2-0c9d3f1b8a57',
        'event_name' => $name,
        'properties' => $properties,
        'user' => null,
        'timestamp' => '2026-11-13T09:30:45+00:00',
        'url' => $url,
        'user_agent_hash' => null,
        'session_id_hash' => null,
    ];
}

/**
 * The size the events endpoint measures: PHP's default `json_encode`, which
 * escapes slashes and spells every non-ASCII character as `\uXXXX`.
 *
 * @param  array<string, mixed>  $item
 */
function serverMeasuredBytes(array $item): int
{
    return mb_strlen((string) json_encode($item), '8bit');
}

/**
 * A products list as a shop passes it to `sale()`, about 150 bytes a product.
 *
 * @return list<array<string, mixed>>
 */
function saleProducts(int $count): array
{
    return array_map(static fn (int $index): array => [
        'id' => "PROD-{$index}",
        'name' => "Organic cotton t-shirt, size M, colour number {$index}",
        'price' => 29.99,
        'quantity' => 2,
        'category' => 'Clothing',
    ], range(1, $count));
}

test('an event within both limits is returned untouched and logs nothing', function (): void {
    $log = new RecordingDiagnostics;
    $item = limitedEvent([
        'order_id' => 'ORD-4821',
        'note' => str_repeat('a', EventLimits::MAX_PROPERTY_VALUE_BYTES),
        'products' => saleProducts(3),
    ], 'https://shop.test/checkout/complete');

    expect((new EventLimits($log))->fit($item))->toBe($item)
        ->and($log->records)->toBe([]);
});

test('an event of exactly the item limit is untouched and one byte more is cut', function (): void {
    $padding = EventLimits::MAX_ITEM_BYTES - serverMeasuredBytes(limitedEvent(['pad' => ['']]));
    $atLimit = limitedEvent(['pad' => [str_repeat('a', $padding)]]);
    $overLimit = limitedEvent(['pad' => [str_repeat('a', $padding + 1)]]);

    expect(serverMeasuredBytes($atLimit))->toBe(EventLimits::MAX_ITEM_BYTES)
        ->and((new EventLimits(new RecordingDiagnostics))->fit($atLimit))->toBe($atLimit)
        ->and((new EventLimits(new RecordingDiagnostics))->fit($overLimit)['properties'])
        ->toBe(['pad' => ['_truncated' => EventLimits::PROPERTY_REPLACED_REASON]]);
});

test('a string property over 500 bytes is cut to at most 500 bytes, the suffix included', function (): void {
    $fitted = (new EventLimits(new RecordingDiagnostics))->fit(limitedEvent(['note' => str_repeat('a', 501)]));

    expect($fitted['properties']['note'])
        ->toBe(str_repeat('a', 485).'... (truncated)')
        ->and(mb_strlen($fitted['properties']['note'], '8bit'))->toBe(EventLimits::MAX_PROPERTY_VALUE_BYTES);
});

test('a multibyte string property is cut on a character boundary', function (): void {
    $fitted = (new EventLimits(new RecordingDiagnostics))->fit(limitedEvent(['note' => str_repeat('é', 300)]));
    $note = $fitted['properties']['note'];

    expect(mb_check_encoding($note, 'UTF-8'))->toBeTrue()
        ->and(mb_strlen($note, '8bit'))->toBeLessThanOrEqual(EventLimits::MAX_PROPERTY_VALUE_BYTES)
        ->and($note)->toBe(str_repeat('é', 242).'... (truncated)');
});

/**
 * The endpoint checks the length of top-level string properties only, so a
 * long string inside a nested value is left as the host wrote it.
 */
test('a long string nested inside a property is left alone', function (): void {
    $item = limitedEvent(['meta' => ['note' => str_repeat('a', 900)]]);

    expect((new EventLimits(new RecordingDiagnostics))->fit($item))->toBe($item);
});

test('an oversize event loses its largest property first and ends within the limit as the server measures it', function (): void {
    $item = limitedEvent([
        'order_id' => 'ORD-4821',
        'products' => saleProducts(40),
        'tags' => array_map(static fn (int $index): string => "tag-{$index}", range(1, 60)),
    ]);

    expect(serverMeasuredBytes($item))->toBeGreaterThan(EventLimits::MAX_ITEM_BYTES);

    $fitted = (new EventLimits(new RecordingDiagnostics))->fit($item);

    expect($fitted['properties']['order_id'])->toBe('ORD-4821')
        ->and($fitted['properties']['tags'])->toBe($item['properties']['tags'])
        ->and($fitted['properties']['products'])->toBe(['_truncated' => EventLimits::PROPERTY_REPLACED_REASON])
        ->and(serverMeasuredBytes($fitted))->toBeLessThanOrEqual(EventLimits::MAX_ITEM_BYTES);
});

/**
 * Measured with escaping switched off, as a careless client would, these
 * events fit. The server encodes with PHP's defaults, so they do not.
 */
test('an event that fits unescaped but not escaped is still cut', function (string $value, int $flags): void {
    $properties = [];

    foreach (range(1, 10) as $index) {
        $properties["part_{$index}"] = $value;
    }

    $item = limitedEvent($properties);

    expect(mb_strlen((string) json_encode($item, $flags), '8bit'))->toBeLessThanOrEqual(EventLimits::MAX_ITEM_BYTES)
        ->and(serverMeasuredBytes($item))->toBeGreaterThan(EventLimits::MAX_ITEM_BYTES);

    $fitted = (new EventLimits(new RecordingDiagnostics))->fit($item);

    expect(serverMeasuredBytes($fitted))->toBeLessThanOrEqual(EventLimits::MAX_ITEM_BYTES)
        ->and($fitted['properties'])->toContain(['_truncated' => EventLimits::PROPERTY_REPLACED_REASON]);
})->with([
    'slashes' => [str_repeat('/', 450), JSON_UNESCAPED_SLASHES],
    'non-ascii' => [str_repeat('é', 225), JSON_UNESCAPED_UNICODE],
]);

test('an event of many small properties has its properties replaced as a whole', function (): void {
    $properties = [];

    foreach (range(1, 600) as $index) {
        $properties["p{$index}"] = 1;
    }

    $fitted = (new EventLimits(new RecordingDiagnostics))->fit(limitedEvent($properties));

    expect($fitted['properties'])->toBe(['_truncated' => EventLimits::PROPERTIES_REPLACED_REASON])
        ->and(serverMeasuredBytes($fitted))->toBeLessThanOrEqual(EventLimits::MAX_ITEM_BYTES);
});

test('an event over the limit with nothing left to replace is dropped and says so', function (): void {
    $log = new RecordingDiagnostics;

    $fitted = (new EventLimits($log))->fit(limitedEvent([], 'https://shop.test/'.str_repeat('é', 1_900), 'search_performed'));

    expect($fitted)->toBeNull()
        ->and($log->records)->toBe([[
            'level' => 'warning',
            'message' => 'Event exceeded the events endpoint limits and was dropped',
            'context' => ['event_name' => 'search_performed', 'max_item_bytes' => EventLimits::MAX_ITEM_BYTES],
        ]]);
});

test('a cut writes one warning naming the event, the properties and the limits that applied', function (): void {
    $log = new RecordingDiagnostics;

    (new EventLimits($log))->fit(limitedEvent([
        'order_id' => 'ORD-4821',
        'note' => str_repeat('n', 600),
        'products' => saleProducts(40),
    ], name: 'sale'));

    expect($log->records)->toBe([[
        'level' => 'warning',
        'message' => 'Event exceeded the events endpoint limits and was cut',
        'context' => [
            'event_name' => 'sale',
            'cut_properties' => ['note'],
            'max_property_value_bytes' => EventLimits::MAX_PROPERTY_VALUE_BYTES,
            'replaced_properties' => ['products'],
            'max_item_bytes' => EventLimits::MAX_ITEM_BYTES,
        ],
    ]]);
});

test('the whole-properties fallback is named in its warning', function (): void {
    $log = new RecordingDiagnostics;
    $properties = [];

    foreach (range(1, 600) as $index) {
        $properties["p{$index}"] = 1;
    }

    (new EventLimits($log))->fit(limitedEvent($properties, name: 'bulk_import'));

    expect($log->records)->toHaveCount(1)
        ->and($log->records[0]['context'])->toBe([
            'event_name' => 'bulk_import',
            'all_properties_replaced' => true,
            'max_item_bytes' => EventLimits::MAX_ITEM_BYTES,
        ]);
});

// Hardening: shapes a host can hand over that the tests above do not.

test('properties given as a list keep their integer keys through a cut and a replacement', function (): void {
    $log = new RecordingDiagnostics;

    $fitted = (new EventLimits($log))->fit(limitedEvent([str_repeat('a', 600), range(1, 1_500)]));

    expect(array_is_list($fitted['properties']))->toBeTrue()
        ->and($fitted['properties'][0])->toBe(str_repeat('a', 485).'... (truncated)')
        ->and($fitted['properties'][1])->toBe(['_truncated' => EventLimits::PROPERTY_REPLACED_REASON])
        ->and($log->records[0]['context']['cut_properties'])->toBe([0])
        ->and($log->records[0]['context']['replaced_properties'])->toBe([1]);
});

test('a null, a float and a boolean property are never replaced, being no larger than the marker', function (): void {
    $fitted = (new EventLimits(new RecordingDiagnostics))->fit(limitedEvent([
        'empty' => null,
        'ratio' => 0.125,
        'flag' => true,
        'blob' => range(1, 1_500),
    ]));

    expect($fitted['properties'])->toBe([
        'empty' => null,
        'ratio' => 0.125,
        'flag' => true,
        'blob' => ['_truncated' => EventLimits::PROPERTY_REPLACED_REASON],
    ]);
});

/**
 * The builder sanitizes and repairs what it is given, so nothing known
 * reaches this point unencodable. Should something, the item would fail the
 * encode of the batch it is sent in, so the property goes and the event stays.
 */
test('a property that cannot be encoded as JSON is replaced and the event is kept', function (mixed $value): void {
    $log = new RecordingDiagnostics;

    $fitted = (new EventLimits($log))->fit(limitedEvent(['order_id' => 'ORD-4821', 'bad' => $value]));

    expect($fitted['properties'])->toBe([
        'order_id' => 'ORD-4821',
        'bad' => ['_truncated' => EventLimits::PROPERTY_REPLACED_REASON],
    ])
        ->and(json_encode($fitted))->not->toBeFalse()
        ->and($log->records[0]['context']['replaced_properties'])->toBe(['bad']);
})->with([
    'infinity' => [INF],
    'invalid utf-8' => ["\xB1\x31"],
    'nested nan' => [['ratio' => NAN]],
]);

test('a long url leaves the properties to give way and arrives whole', function (): void {
    $url = 'https://shop.test/search?q='.str_repeat('a', 1_900);
    $item = limitedEvent([
        'query_id' => 'Q-1',
        'filters' => array_map(static fn (int $index): string => "category-name-{$index}", range(1, 30)),
        'results' => range(100_000, 100_399),
    ], $url);

    expect(serverMeasuredBytes($item))->toBeGreaterThan(EventLimits::MAX_ITEM_BYTES);

    $fitted = (new EventLimits(new RecordingDiagnostics))->fit($item);

    expect($fitted['url'])->toBe($url)
        ->and($fitted['properties']['query_id'])->toBe('Q-1')
        ->and($fitted['properties']['filters'])->toBe($item['properties']['filters'])
        ->and($fitted['properties']['results'])->toBe(['_truncated' => EventLimits::PROPERTY_REPLACED_REASON])
        ->and(serverMeasuredBytes($fitted))->toBeLessThanOrEqual(EventLimits::MAX_ITEM_BYTES);
});

test('a diagnostics sink that throws costs neither the cut nor the caller', function (): void {
    $fitted = (new EventLimits(new RecordingDiagnostics(throws: true)))->fit(limitedEvent(['products' => saleProducts(40)]));

    expect($fitted['properties']['products'])->toBe(['_truncated' => EventLimits::PROPERTY_REPLACED_REASON]);
});

test('a dropped event with a sink that throws is still dropped without throwing', function (): void {
    expect((new EventLimits(new RecordingDiagnostics(throws: true)))->fit(limitedEvent([], 'https://shop.test/'.str_repeat('é', 1_900))))
        ->toBeNull();
});

test('an item without a properties key is never given one', function (): void {
    $item = limitedEvent([], 'https://shop.test/'.str_repeat('é', 1_900));
    unset($item['properties']);

    expect((new EventLimits(new RecordingDiagnostics))->fit($item))->toBeNull();
});
