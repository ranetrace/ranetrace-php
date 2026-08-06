<?php

declare(strict_types=1);

use Ranetrace\Php\JavaScript\Relay;
use Ranetrace\Php\Support\FingerprintGenerator;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;
use Ranetrace\Php\Tests\Doubles\ArrayBuffer;

/**
 * The exact key set the javascript-errors endpoint accepts, in wire order.
 *
 * @var array<int, string>
 */
const JAVASCRIPT_ERROR_KEYS = [
    'message',
    'stack',
    'type',
    'filename',
    'line',
    'column',
    'user_agent',
    'url',
    'timestamp',
    'environment',
    'user_id',
    'session_id',
    'breadcrumbs',
    'context',
    'browser_info',
];

/**
 * @param  array<string, mixed>  $overrides  Merged into `javascript_errors`.
 * @param  array<string, mixed>  $root  Merged into the root config.
 */
function relay(ArrayBuffer $buffer, array $overrides = [], array $root = []): Relay
{
    $config = testConfig(array_replace([
        'environment' => 'testing',
        'javascript_errors' => array_replace(['enabled' => true], $overrides),
        'internal_logging' => ['enabled' => false],
    ], $root));

    return new Relay(
        $config,
        $buffer,
        new SecretScrubber($config),
        new FingerprintGenerator($config),
        new InternalLogger($config),
    );
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function relayServer(array $overrides = []): array
{
    return array_replace([
        'HTTP_HOST' => 'app.test',
        'HTTP_ORIGIN' => 'https://app.test',
        'HTTP_USER_AGENT' => 'Test Browser',
    ], $overrides);
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function relayPayload(array $overrides = []): array
{
    return array_replace([
        'message' => 'Cannot read properties of undefined',
        'stack' => 'Error: boom\n at app.js:1:1',
        'type' => 'TypeError',
        'filename' => 'https://app.test/app.js',
        'line' => 12,
        'column' => 34,
        'url' => 'https://app.test/checkout',
        'timestamp' => '2026-08-06T10:00:00+00:00',
    ], $overrides);
}

/**
 * @return array<string, mixed>
 */
function firstJavascriptError(ArrayBuffer $buffer): array
{
    return $buffer->payloads('javascript_errors')[0];
}

test('it rejects the report when the sdk itself is off', function (array $root): void {
    $buffer = new ArrayBuffer;

    $response = relay($buffer, [], $root)->handleRequest(relayServer(), relayPayload());

    expect($response->status)->toBe(403)
        ->and($response->body)->toBe(['success' => false, 'message' => 'Ranetrace is not enabled'])
        ->and($buffer->count('javascript_errors'))->toBe(0);
})->with([
    'sdk disabled' => [['enabled' => false]],
    'no api key' => [['key' => '']],
]);

test('it rejects the report when javascript error tracking is off', function (): void {
    $buffer = new ArrayBuffer;

    $response = relay($buffer, ['enabled' => false])->handleRequest(relayServer(), relayPayload());

    expect($response->status)->toBe(403)
        ->and($response->body)->toBe(['success' => false, 'message' => 'JavaScript error tracking is not enabled']);
});

test('it accepts a request whose origin matches the host it was sent to', function (string $origin, string $host): void {
    $buffer = new ArrayBuffer;

    $response = relay($buffer)->handleRequest(
        relayServer(['HTTP_ORIGIN' => $origin, 'HTTP_HOST' => $host]),
        relayPayload(),
    );

    expect($response->status)->toBe(200)
        ->and($response->body)->toBe(['success' => true, 'message' => 'Error received']);
})->with([
    'plain' => ['https://app.test', 'app.test'],
    'default port spelled out' => ['https://app.test:443', 'app.test'],
    'explicit port on both sides' => ['http://app.test:8080', 'app.test:8080'],
    'case insensitive' => ['https://APP.test', 'app.TEST'],
]);

test('it rejects a cross origin report, which is what replaces the csrf token here', function (): void {
    $buffer = new ArrayBuffer;

    $response = relay($buffer)->handleRequest(
        relayServer(['HTTP_ORIGIN' => 'https://evil.test']),
        relayPayload(),
    );

    expect($response->status)->toBe(403)
        ->and($response->body)->toBe(['success' => false, 'message' => 'Origin not allowed'])
        ->and($buffer->count('javascript_errors'))->toBe(0);
});

test('it rejects an origin header it cannot parse rather than failing open', function (): void {
    $response = relay(new ArrayBuffer)->handleRequest(
        relayServer(['HTTP_ORIGIN' => 'not-an-origin']),
        relayPayload(),
    );

    expect($response->status)->toBe(403)
        ->and($response->body['message'])->toBe('Origin not allowed');
});

test('it falls back to the referer when there is no origin header', function (): void {
    $response = relay(new ArrayBuffer)->handleRequest(
        ['HTTP_HOST' => 'app.test', 'HTTP_REFERER' => 'https://evil.test/page'],
        relayPayload(),
    );

    expect($response->status)->toBe(403)
        ->and($response->body['message'])->toBe('Origin not allowed');
});

test('a request with neither origin nor referer is allowed', function (): void {
    $response = relay(new ArrayBuffer)->handleRequest(['HTTP_HOST' => 'app.test'], relayPayload());

    expect($response->status)->toBe(200);
});

test('a configured allowed origin is accepted, in either spelling', function (string $allowed): void {
    $response = relay(new ArrayBuffer, ['allowed_origins' => [$allowed]])->handleRequest(
        relayServer(['HTTP_ORIGIN' => 'https://cdn.other.test']),
        relayPayload(),
    );

    expect($response->status)->toBe(200);
})->with([
    'full origin' => ['https://cdn.other.test'],
    'bare authority' => ['cdn.other.test'],
]);

test('the referer fills a blank url before validation runs', function (mixed $url): void {
    $buffer = new ArrayBuffer;

    $response = relay($buffer)->handleRequest(
        relayServer(['HTTP_REFERER' => 'https://app.test/from-referer']),
        relayPayload(['url' => $url]),
    );

    expect($response->status)->toBe(200)
        ->and(firstJavascriptError($buffer)['url'])->toBe('https://app.test/from-referer');
})->with([
    'null' => [null],
    'empty' => [''],
    'whitespace' => ['   '],
]);

test('a blank url with no referer fails validation, so url is always present', function (): void {
    $response = relay(new ArrayBuffer)->handleRequest(relayServer(), relayPayload(['url' => null]));

    expect($response->status)->toBe(422)
        ->and($response->body['success'])->toBeFalse()
        ->and($response->body['message'])->toBe('Validation failed')
        ->and($response->body['errors'])->toHaveKey('url');
});

test('it reports the fields that failed validation', function (array $overrides, array $expectedKeys): void {
    $buffer = new ArrayBuffer;

    $response = relay($buffer)->handleRequest(relayServer(), relayPayload($overrides));

    expect($response->status)->toBe(422)
        ->and($response->body['message'])->toBe('Validation failed')
        ->and(array_keys($response->body['errors']))->toBe($expectedKeys)
        ->and($buffer->count('javascript_errors'))->toBe(0);
})->with([
    'missing message' => [['message' => null], ['message']],
    'blank message' => [['message' => '  '], ['message']],
    'message too long' => [['message' => str_repeat('a', 2001)], ['message']],
    'message not a string' => [['message' => ['nope']], ['message']],
    'stack too long' => [['stack' => str_repeat('a', 10001)], ['stack']],
    'type too long' => [['type' => str_repeat('a', 101)], ['type']],
    'filename too long' => [['filename' => str_repeat('a', 501)], ['filename']],
    'line not an integer' => [['line' => 'twelve'], ['line']],
    'column not an integer' => [['column' => 1.5], ['column']],
    'url too long' => [['url' => 'https://app.test/'.str_repeat('a', 2001)], ['url']],
    'timestamp not a string' => [['timestamp' => 1754472000], ['timestamp']],
    'breadcrumbs not an array' => [['breadcrumbs' => 'nope'], ['breadcrumbs']],
    'context not an array' => [['context' => 'nope'], ['context']],
    'browser_info not an array' => [['browser_info' => 'nope'], ['browser_info']],
    'several at once' => [['message' => null, 'line' => 'twelve'], ['message', 'line']],
]);

test('it validates every breadcrumb by its index', function (): void {
    $response = relay(new ArrayBuffer)->handleRequest(relayServer(), relayPayload([
        'breadcrumbs' => [
            ['timestamp' => '2026-08-06T10:00:00Z', 'category' => 'user', 'message' => 'Click'],
            ['category' => str_repeat('a', 101), 'message' => str_repeat('b', 501), 'data' => 'nope'],
        ],
    ]));

    expect($response->status)->toBe(422)
        ->and(array_keys($response->body['errors']))->toBe([
            'breadcrumbs.1.timestamp',
            'breadcrumbs.1.category',
            'breadcrumbs.1.message',
            'breadcrumbs.1.data',
        ]);
});

test('it validates the browser info fields', function (): void {
    $response = relay(new ArrayBuffer)->handleRequest(relayServer(), relayPayload([
        'browser_info' => [
            'screen_width' => 'wide',
            'hardware_concurrency' => [],
            'connection_type' => str_repeat('a', 51),
        ],
    ]));

    expect($response->status)->toBe(422)
        ->and(array_keys($response->body['errors']))->toBe([
            'browser_info.screen_width',
            'browser_info.hardware_concurrency',
            'browser_info.connection_type',
        ]);
});

test('a valid but noisy message is acknowledged and dropped', function (string $message): void {
    $buffer = new ArrayBuffer;

    $response = relay($buffer)->handleRequest(relayServer(), relayPayload(['message' => $message]));

    expect($response->status)->toBe(200)
        ->and($response->body)->toBe(['success' => true, 'message' => 'Error ignored based on pattern'])
        ->and($buffer->count('javascript_errors'))->toBe(0);
})->with([
    'exact' => ['ResizeObserver loop limit exceeded'],
    'substring' => ['Uncaught Error: Loading chunk 42 failed'],
    'different case' => ['SCRIPT ERROR.'],
]);

test('a configured pattern list replaces the defaults', function (): void {
    $buffer = new ArrayBuffer;

    $relay = relay($buffer, ['ignored_errors' => ['only this']]);

    expect($relay->handleRequest(relayServer(), relayPayload(['message' => 'Script error.']))->body['message'])
        ->toBe('Error received')
        ->and($relay->handleRequest(relayServer(), relayPayload(['message' => 'ONLY THIS one']))->body['message'])
        ->toBe('Error ignored based on pattern');
});

test('a sampled out report is acknowledged and dropped', function (): void {
    $buffer = new ArrayBuffer;

    $response = relay($buffer, ['sample_rate' => 0.0])->handleRequest(relayServer(), relayPayload());

    expect($response->status)->toBe(200)
        ->and($response->body)->toBe(['success' => true, 'message' => 'Error sampled out'])
        ->and($buffer->count('javascript_errors'))->toBe(0);
});

test('it buffers exactly the fifteen wire keys, in order', function (): void {
    $buffer = new ArrayBuffer;

    relay($buffer)->handleRequest(relayServer(), relayPayload());

    expect($buffer->count('javascript_errors'))->toBe(1)
        ->and(array_keys(firstJavascriptError($buffer)))->toBe(JAVASCRIPT_ERROR_KEYS);
});

test('it keeps the browser reported fields and adds the server side ones', function (): void {
    $buffer = new ArrayBuffer;

    relay($buffer, [], ['user_resolver' => fn (): array => ['id' => 77, 'email' => 'a@b.test']])
        ->handleRequest(relayServer(), relayPayload());

    expect(firstJavascriptError($buffer))->toMatchArray([
        'message' => 'Cannot read properties of undefined',
        'type' => 'TypeError',
        'filename' => 'https://app.test/app.js',
        'line' => 12,
        'column' => 34,
        'user_agent' => 'Test Browser',
        'url' => 'https://app.test/checkout',
        'timestamp' => '2026-08-06T10:00:00+00:00',
        'environment' => 'testing',
        'user_id' => 77,
        'breadcrumbs' => [],
        'context' => [],
    ]);
});

test('the type defaults to Error and the timestamp to now', function (): void {
    $buffer = new ArrayBuffer;

    relay($buffer)->handleRequest(relayServer(), relayPayload(['type' => null, 'timestamp' => null]));

    $item = firstJavascriptError($buffer);

    expect($item['type'])->toBe('Error')
        ->and($item['timestamp'])->toMatch('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/');
});

test('the optional browser fields are null rather than absent when not reported', function (): void {
    $buffer = new ArrayBuffer;

    relay($buffer)->handleRequest(relayServer(['HTTP_USER_AGENT' => null]), [
        'message' => 'boom',
        'url' => 'https://app.test/',
    ]);

    expect(firstJavascriptError($buffer))->toMatchArray([
        'stack' => null,
        'filename' => null,
        'line' => null,
        'column' => null,
        'user_agent' => null,
        'user_id' => null,
        'session_id' => null,
    ]);
});

test('it scrubs the stack and the query string of the reported url', function (): void {
    $buffer = new ArrayBuffer;

    relay($buffer)->handleRequest(relayServer(), relayPayload([
        'stack' => 'Error: failed with api_key=sk_live_123 at app.js:1:1',
        'url' => 'https://app.test/reset/abc123?token=secret&page=2',
    ]));

    $item = firstJavascriptError($buffer);

    expect($item['stack'])->toBe('Error: failed with api_key=[REDACTED] at app.js:1:1')
        ->and($item['url'])->toBe('https://app.test/reset/abc123?token=[REDACTED]&page=2');
});

test('it redacts host declared sensitive path segments from the reported url', function (): void {
    $buffer = new ArrayBuffer;

    $relay = relay($buffer);
    $relay->setSensitivePathValues(['abc123']);
    $relay->handleRequest(relayServer(), relayPayload(['url' => 'https://app.test/reset/abc123?page=2']));

    expect(firstJavascriptError($buffer)['url'])->toBe('https://app.test/reset/[REDACTED]?page=2');
});

test('it keeps only the last breadcrumbs and rebuilds each as the four wire keys', function (): void {
    $buffer = new ArrayBuffer;

    $breadcrumbs = [];

    for ($index = 0; $index < 6; $index++) {
        $breadcrumbs[] = [
            'timestamp' => '2026-08-06T10:00:0'.$index.'+00:00',
            'category' => 'user',
            'message' => 'Click '.$index,
            'data' => ['tag' => 'button'],
            'smuggled' => 'should not survive',
        ];
    }

    relay($buffer, ['max_breadcrumbs' => 3])->handleRequest(relayServer(), relayPayload([
        'breadcrumbs' => $breadcrumbs,
    ]));

    $kept = firstJavascriptError($buffer)['breadcrumbs'];

    expect($kept)->toHaveCount(3)
        ->and(array_column($kept, 'message'))->toBe(['Click 3', 'Click 4', 'Click 5'])
        ->and(array_keys($kept[0]))->toBe(['timestamp', 'category', 'message', 'data'])
        ->and($kept[0]['data'])->toBe(['tag' => 'button']);
});

test('it scrubs breadcrumb data and replaces it wholesale when it is oversize', function (): void {
    $buffer = new ArrayBuffer;

    relay($buffer)->handleRequest(relayServer(), relayPayload([
        'breadcrumbs' => [
            [
                'timestamp' => '2026-08-06T10:00:00+00:00',
                'category' => 'http',
                'message' => 'Fetch completed',
                'data' => ['authorization' => 'Bearer abc', 'status' => 200],
            ],
            [
                'timestamp' => '2026-08-06T10:00:01+00:00',
                'category' => 'http',
                'message' => 'Fetch completed',
                'data' => ['body' => str_repeat('a', 6000)],
            ],
        ],
    ]));

    $kept = firstJavascriptError($buffer)['breadcrumbs'];

    expect($kept[0]['data'])->toBe(['authorization' => '[REDACTED]', 'status' => 200])
        ->and($kept[1]['data'])->toBe(['_truncated' => 'Breadcrumb data exceeded 5KB limit and was removed']);
});

test('it scrubs the context and replaces it wholesale when it is oversize', function (): void {
    $buffer = new ArrayBuffer;
    $relay = relay($buffer);

    $relay->handleRequest(relayServer(), relayPayload(['context' => ['api_token' => 'abc', 'step' => 'checkout']]));
    $relay->handleRequest(relayServer(), relayPayload([
        'message' => 'a different message so dedup is not a factor',
        'context' => ['blob' => str_repeat('a', 60000)],
    ]));

    $items = $buffer->payloads('javascript_errors');

    expect($items[0]['context'])->toBe(['api_token' => '[REDACTED]', 'step' => 'checkout'])
        ->and($items[1]['context'])->toBe(['_truncated' => 'Context exceeded 50KB limit and was removed']);
});

test('browser info is rebuilt as exactly seven keys, dropping unknown ones', function (): void {
    $buffer = new ArrayBuffer;

    relay($buffer)->handleRequest(relayServer(), relayPayload([
        'browser_info' => [
            'screen_width' => 1920,
            'connection_type' => '4g',
            'smuggled' => 'should not survive',
        ],
    ]));

    expect(firstJavascriptError($buffer)['browser_info'])->toBe([
        'screen_width' => 1920,
        'screen_height' => null,
        'viewport_width' => null,
        'viewport_height' => null,
        'device_memory' => null,
        'hardware_concurrency' => null,
        'connection_type' => '4g',
    ]);
});

test('browser info is still the full seven keys when the browser sent none', function (): void {
    $buffer = new ArrayBuffer;

    relay($buffer)->handleRequest(relayServer(), relayPayload());

    expect(array_keys(firstJavascriptError($buffer)['browser_info']))->toBe([
        'screen_width',
        'screen_height',
        'viewport_width',
        'viewport_height',
        'device_memory',
        'hardware_concurrency',
        'connection_type',
    ]);
});

test('the session id is hashed, never sent raw', function (): void {
    $buffer = new ArrayBuffer;
    $config = testConfig(['environment' => 'testing', 'internal_logging' => ['enabled' => false]]);

    relay($buffer)->handleRequest(
        relayServer(['RANETRACE_SESSION_ID' => 'raw-session-value']),
        relayPayload(),
    );

    $sessionId = firstJavascriptError($buffer)['session_id'];

    expect($sessionId)->toBe((new FingerprintGenerator($config))->hash('raw-session-value'))
        ->and($sessionId)->not->toBe('raw-session-value')
        ->and($sessionId)->toHaveLength(64);
});

test('the session id is null when the host supplied none, never a hash of nothing', function (): void {
    $buffer = new ArrayBuffer;

    relay($buffer)->handleRequest(relayServer(['RANETRACE_SESSION_ID' => '']), relayPayload());

    expect(firstJavascriptError($buffer)['session_id'])->toBeNull();
});

test('a rejected buffer write is acknowledged, because the browser cannot fix it', function (): void {
    $buffer = new ArrayBuffer;
    $buffer->rejectWrites = true;

    $response = relay($buffer)->handleRequest(relayServer(), relayPayload());

    expect($response->status)->toBe(200)
        ->and($response->body)->toBe(['success' => true, 'message' => 'Error received'])
        ->and($buffer->count('javascript_errors'))->toBe(0);
});

test('an unexpected failure becomes a 500 body rather than an exception into the host', function (): void {
    $buffer = new ArrayBuffer;

    $response = relay($buffer, [], [
        'user_resolver' => function (): array {
            throw new RuntimeException('resolver exploded');
        },
    ])->handleRequest(relayServer(), relayPayload());

    expect($response->status)->toBe(500)
        ->and($response->body)->toBe(['success' => false, 'message' => 'Failed to process error'])
        ->and($buffer->count('javascript_errors'))->toBe(0);
});

test('the superglobal adapter writes the json body out', function (): void {
    // php://input is empty under the CLI SAPI, so this exercises the decode
    // fallback: no body becomes an empty payload, which fails validation.
    ob_start();
    relay(new ArrayBuffer)->handle();
    $output = (string) ob_get_clean();

    $decoded = json_decode($output, true, 512, JSON_THROW_ON_ERROR);

    expect($decoded['success'])->toBeFalse()
        ->and($decoded['message'])->toBe('Validation failed')
        ->and(array_keys($decoded['errors']))->toBe(['message', 'url']);
});

test('the response encodes itself as json', function (): void {
    $response = relay(new ArrayBuffer)->handleRequest(relayServer(), relayPayload());

    expect($response->toJson())->toBe('{"success":true,"message":"Error received"}');
});
