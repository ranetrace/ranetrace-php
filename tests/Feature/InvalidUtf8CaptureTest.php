<?php

declare(strict_types=1);

use Monolog\Logger;
use Ranetrace\Php\Ranetrace;
use Ranetrace\Php\Tests\Doubles\FakeHttpClient;

/**
 * One invalid UTF-8 byte, followed from capture through the file buffer, the
 * worker and the API client to the request body the API would receive.
 *
 * The realistic source is a database driver message carrying latin1 bytes. The
 * wire is JSON, and `json_encode` refuses the whole value it is handed when one
 * string in it is not UTF-8, so these tests pin that the item arrives with the
 * byte replaced and that the valid item captured beside it arrives untouched.
 */
function invalidUtf8Sdk(FakeHttpClient $http, array $overrides = []): Ranetrace
{
    return new Ranetrace(array_replace_recursive([
        'key' => 'test-api-key-12345',
        'buffer_path' => tempDirectory(),
        'flush_on_shutdown' => false,
        'internal_logging' => ['enabled' => false],
    ], $overrides))->withHttpClient($http);
}

test('an error whose message holds an invalid byte is sent with the byte replaced, beside a valid one', function (): void {
    $http = FakeHttpClient::respondingWith(200);
    $sdk = invalidUtf8Sdk($http);

    $sdk->report(new RuntimeException("SQLSTATE[HY000]: Incorrect string value: '\xB1' for column 'name'"));
    $sdk->report(new RuntimeException('A valid message'));

    $sdk->flush('errors');

    expect($http->requests)->toHaveCount(1)
        ->and(array_column($http->payload()['errors'], 'message'))->toBe([
            "SQLSTATE[HY000]: Incorrect string value: '\u{FFFD}' for column 'name'",
            'A valid message',
        ])
        ->and($sdk->buffer()->count('errors'))->toBe(0);
});

test('a log record with an invalid byte in its message and deep in its context is sent repaired', function (): void {
    $http = FakeHttpClient::respondingWith(200);
    $sdk = invalidUtf8Sdk($http, ['logging' => ['enabled' => true]]);
    $logger = new Logger('app', [$sdk->monologHandler()]);

    $logger->error("Import failed on row \xB1", ['row' => ['fields' => ['name' => "Jos\xE9", "k\xB1" => 'value']]]);
    $logger->error('A valid record');

    $sdk->flush('logs');

    $logs = $http->payload()['logs'];

    expect($http->requests)->toHaveCount(1)
        ->and(array_column($logs, 'message'))->toBe(["Import failed on row \u{FFFD}", 'A valid record'])
        ->and($logs[0]['context'])->toBe(['row' => ['fields' => ['name' => "Jos\u{FFFD}", "k\u{FFFD}" => 'value']]]);
});

test('an event with an invalid byte in a property key and value is sent repaired', function (): void {
    $http = FakeHttpClient::respondingWith(200);
    $sdk = invalidUtf8Sdk($http);

    $sdk->trackEvent('order_placed', ["customer\xB1" => "Jos\xE9"]);
    $sdk->trackEvent('order_placed', ['customer' => 'valid']);

    $sdk->flush('events');

    expect($http->requests)->toHaveCount(1)
        ->and(array_column($http->payload()['events'], 'properties'))->toBe([
            ["customer\u{FFFD}" => "Jos\u{FFFD}"],
            ['customer' => 'valid'],
        ]);
});

test('a browser error relayed with invalid bytes is sent repaired', function (): void {
    $http = FakeHttpClient::respondingWith(200);
    $sdk = invalidUtf8Sdk($http, ['javascript_errors' => ['enabled' => true]]);

    $response = $sdk->relay()->handleRequest(['HTTP_USER_AGENT' => "Agent\xB1"], [
        'message' => "Bad \xB1 input",
        'url' => "https://example.test/caf\xE9",
        'context' => ["key\xB1" => ['nested' => "value\xB1"]],
        'breadcrumbs' => [
            ['timestamp' => 't', 'category' => "nav\xB1", 'message' => "went \xB1", 'data' => ["d\xB1" => "v\xB1"]],
        ],
    ]);

    $sdk->flush('javascript_errors');

    $item = $http->payload()['javascript_errors'][0] ?? [];

    expect($response->status)->toBe(200)
        ->and($http->requests)->toHaveCount(1)
        ->and($item['message'])->toBe("Bad \u{FFFD} input")
        ->and($item['url'])->toBe("https://example.test/caf\u{FFFD}")
        ->and($item['user_agent'])->toBe("Agent\u{FFFD}")
        ->and($item['context'])->toBe(["key\u{FFFD}" => ['nested' => "value\u{FFFD}"]])
        ->and($item['breadcrumbs'][0])->toBe([
            'timestamp' => 't',
            'category' => "nav\u{FFFD}",
            'message' => "went \u{FFFD}",
            'data' => ["d\u{FFFD}" => "v\u{FFFD}"],
        ]);
});
