<?php

declare(strict_types=1);

use Ranetrace\Php\Contract\WireContract;

test('it loads every described item type', function (string $type): void {
    expect(WireContract::item($type))->toHaveKeys(['type', 'wrapper', 'fields', 'examples']);
})->with(WireContract::describedItemTypes());

test('it describes the page visit only the laravel sdk sends, beside the four types this package sends', function (): void {
    // The buffer, the worker and the endpoint table are built from
    // itemTypes(), so a type this package cannot send must stay out of it.
    expect(WireContract::itemTypes())->toBe(['errors', 'events', 'logs', 'javascript_errors'])
        ->and(WireContract::describedItemTypes())->toBe([...WireContract::itemTypes(), 'page_visits']);
});

test('it rejects a type the contract does not describe', function (): void {
    WireContract::item('metrics');
})->throws(InvalidArgumentException::class, "Unknown Ranetrace item type 'metrics'");

test('it loads the envelope, endpoints, headers and responses', function (): void {
    expect(WireContract::envelope())->toHaveKeys(['request_body', 'buffered_item', 'wrappers', 'max_items_per_batch'])
        ->and(WireContract::endpoints())->toHaveKey('endpoints')
        ->and(WireContract::headers())->toHaveKeys(['api_version', 'request'])
        ->and(WireContract::responses())->toHaveKeys(['statuses', 'success_body', 'error_body']);
});

/**
 * A consuming repository locates the fixtures through this path, so it has to
 * resolve from wherever the package is installed rather than from a cwd.
 */
test('it exposes a base path that resolves to the shipped fixtures', function (): void {
    expect(WireContract::basePath())->toBeDirectory()
        ->and(WireContract::basePath().'/items/errors.json')->toBeFile();
});
