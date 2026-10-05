<?php

declare(strict_types=1);

use Monolog\Logger;
use Ranetrace\Php\Ranetrace;
use Ranetrace\Php\Tests\Doubles\FakeHttpClient;

/**
 * A float JSON has no spelling for (INF, -INF, NAN), followed from capture
 * through the file buffer, the worker and the API client to the request body
 * the API would receive.
 *
 * A log record's context and extra and an event's properties are free-shape,
 * so a ratio divided by zero lands there in practice. `json_encode` refuses the
 * whole value it is handed when one float in it is not finite, so these tests
 * pin that the item arrives with the float spelled as a string and that the
 * valid item captured beside it arrives untouched.
 */
function nonFiniteSdk(FakeHttpClient $http, array $overrides = []): Ranetrace
{
    return new Ranetrace(array_replace_recursive([
        'key' => 'test-api-key-12345',
        'buffer_path' => tempDirectory(),
        'flush_on_shutdown' => false,
        'internal_logging' => ['enabled' => false],
    ], $overrides))->withHttpClient($http);
}

test('a log record with INF in its context is sent with the string INF, beside a valid one', function (): void {
    $http = FakeHttpClient::respondingWith(200);
    $sdk = nonFiniteSdk($http, ['logging' => ['enabled' => true]]);
    $logger = new Logger('app', [$sdk->monologHandler()]);

    $logger->error('Conversion ratio computed', ['ratio' => INF, 'nested' => ['drift' => -INF]]);
    $logger->error('A valid record', ['ratio' => 0.5]);

    $sdk->flush('logs');

    $logs = $http->payload()['logs'] ?? [];

    expect($http->requests)->toHaveCount(1)
        ->and(array_column($logs, 'message'))->toBe(['Conversion ratio computed', 'A valid record'])
        ->and($logs[0]['context'])->toBe(['ratio' => 'INF', 'nested' => ['drift' => '-INF']])
        ->and($logs[1]['context'])->toBe(['ratio' => 0.5])
        ->and($sdk->buffer()->count('logs'))->toBe(0);
});

test('a log record with NAN in its extra is sent with the string NAN', function (): void {
    $http = FakeHttpClient::respondingWith(200);
    $sdk = nonFiniteSdk($http, ['logging' => ['enabled' => true]]);
    $logger = new Logger('app', [$sdk->monologHandler()]);
    $logger->pushProcessor(static function (Monolog\LogRecord $record): Monolog\LogRecord {
        return $record->with(extra: ['score' => NAN]);
    });

    $logger->error('Scored');

    $sdk->flush('logs');

    expect($http->requests)->toHaveCount(1)
        ->and(($http->payload()['logs'][0] ?? [])['extra']['score'] ?? null)->toBe('NAN');
});

test('an event with NAN and -INF properties is sent with the strings, beside a valid one', function (): void {
    $http = FakeHttpClient::respondingWith(200);
    $sdk = nonFiniteSdk($http);

    $sdk->trackEvent('report_generated', ['average' => NAN, 'trend' => -INF]);
    $sdk->trackEvent('report_generated', ['average' => 1.5]);

    $sdk->flush('events');

    expect($http->requests)->toHaveCount(1)
        ->and(array_column($http->payload()['events'] ?? [], 'properties'))->toBe([
            ['average' => 'NAN', 'trend' => '-INF'],
            ['average' => 1.5],
        ])
        ->and($sdk->buffer()->count('events'))->toBe(0);
});
