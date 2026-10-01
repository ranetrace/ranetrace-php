<?php

declare(strict_types=1);

use Ranetrace\Php\Events\EventItemBuilder;
use Ranetrace\Php\JavaScript\ErrorItemBuilder;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;

/**
 * `ranetrace/ranetrace-laravel` hands these builders a user id straight from
 * its own auth (`getAuthIdentifier()`), past this package's resolvers, so the
 * builders are where an id the backend would reject is dropped for both SDKs.
 */
test('the event item builder sends no user when the id is one the backend would reject', function (mixed $id): void {
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    $item = (new EventItemBuilder(new SecretScrubber($config, new InternalLogger($config))))
        ->build('user_logged_in', [], ['id' => $id], '2026-10-01T09:30:45+00:00', null, '', '');

    expect($item['user'])->toBeNull();
})->with([
    'null' => [null],
    'float' => [42.0],
    'boolean' => [true],
    'array' => [[42]],
    'object' => [new stdClass],
    'string past 255 characters' => [str_repeat('a', 256)],
]);

test('the event item builder sends an id the backend takes as it is', function (int|string $id): void {
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    $item = (new EventItemBuilder(new SecretScrubber($config, new InternalLogger($config))))
        ->build('user_logged_in', [], ['id' => $id], '2026-10-01T09:30:45+00:00', null, '', '');

    expect($item['user'])->toBe(['id' => $id]);
})->with([
    'integer' => [42],
    'string' => ['usr_42'],
    'string at 255 characters' => [str_repeat('é', 255)],
]);

test('the javascript error item builder nulls a user id past 255 characters and keeps one at the bound', function (): void {
    $config = testConfig(['internal_logging' => ['enabled' => false]]);
    $builder = new ErrorItemBuilder($config, new SecretScrubber($config, new InternalLogger($config)));
    $atBound = str_repeat('é', 255);

    expect($builder->build(['message' => 'Boom'], null, str_repeat('a', 256), null)['user_id'])->toBeNull()
        ->and($builder->build(['message' => 'Boom'], null, $atBound, null)['user_id'])->toBe($atBound)
        ->and($builder->build(['message' => 'Boom'], null, 42, null)['user_id'])->toBe(42);
});
