<?php

declare(strict_types=1);

use Ranetrace\Php\JavaScript\ErrorItemBuilder;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;

/**
 * `line` and `column` are integers on the wire. The relay takes a decoded array
 * from its host, which can hold a float no integer can represent; casting one
 * warns on PHP 8.5, and a host that turns warnings into exceptions would lose
 * the report to it. Such a value is not a position, so it is sent as null.
 */
test('a line or column no integer can represent is sent as null', function (mixed $value): void {
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    set_error_handler(static function (int $level, string $message): never {
        throw new ErrorException($message, 0, $level);
    });

    try {
        $item = (new ErrorItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))->build([
            'message' => 'Chart failed',
            'url' => 'https://example.test/report',
            'line' => $value,
            'column' => $value,
        ], null, null, null);
    } finally {
        restore_error_handler();
    }

    expect($item['line'])->toBeNull()
        ->and($item['column'])->toBeNull();
})->with([
    'infinity' => [INF],
    'negative infinity' => [-INF],
    'not a number' => [NAN],
    'a float past the integer range' => [1e20],
    'a numeric string past the integer range' => ['1e400'],
]);

test('a line or column an integer can represent is still sent as that integer', function (mixed $value, int $expected): void {
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    $item = (new ErrorItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))->build([
        'message' => 'Chart failed',
        'url' => 'https://example.test/report',
        'line' => $value,
    ], null, null, null);

    expect($item['line'])->toBe($expected);
})->with([
    'an integer' => [12, 12],
    'a numeric string' => ['12', 12],
    'a whole float' => [12.0, 12],
]);
