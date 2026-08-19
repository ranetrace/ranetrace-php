<?php

declare(strict_types=1);

use Ranetrace\Php\Contract\WireContract;

test('it loads every declared item type', function (string $type): void {
    expect(WireContract::item($type))->toHaveKeys(['type', 'wrapper', 'fields', 'examples']);
})->with(WireContract::itemTypes());

test('it rejects a type the contract does not describe', function (): void {
    WireContract::item('page_visits');
})->throws(InvalidArgumentException::class, "Unknown Ranetrace item type 'page_visits'");

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
