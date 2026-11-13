<?php

declare(strict_types=1);

use Ranetrace\Php\Errors\ErrorContext;
use Ranetrace\Php\Errors\PayloadBuilder;
use Ranetrace\Php\JavaScript\ErrorItemBuilder;
use Ranetrace\Php\JavaScript\Relay;
use Ranetrace\Php\Logging\LogItemBuilder;
use Ranetrace\Php\Support\Diagnostics;
use Ranetrace\Php\Support\EnvironmentName;
use Ranetrace\Php\Support\FingerprintGenerator;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;
use Ranetrace\Php\Tests\Doubles\ArrayBuffer;
use Ranetrace\Php\Tests\Doubles\RecordingDiagnostics;

/**
 * The endpoints refuse an item with one string field over its limit, and a
 * refused item is final, so the shared builders cut every such field to the
 * limit `contract/items/*.json` states, counted in characters as the endpoints
 * count. Free text keeps its start and ends in the truncation suffix; a name
 * keeps its first characters and nothing else. Most cases use multibyte
 * characters, so a cut that counted bytes would fail them.
 *
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function limitsErrorItem(array $overrides = [], ?ErrorContext $context = null, ?Diagnostics $log = null): array
{
    $config = testConfig(array_replace_recursive([
        'internal_logging' => ['enabled' => false],
        'errors' => ['capture_source' => false],
    ], $overrides));
    $internal = new InternalLogger($config);

    return (new PayloadBuilder($config, new SecretScrubber($config, $internal), $log ?? $internal))
        ->build(new RuntimeException('Something broke'), $context ?? ErrorContext::provided(isConsole: true));
}

/**
 * @param  array<string, mixed>  $payload  Merged over a minimal valid payload.
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function limitsJavaScriptItem(array $payload, array $overrides = []): array
{
    $config = testConfig(array_replace(['internal_logging' => ['enabled' => false]], $overrides));

    return (new ErrorItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))->build(
        array_replace(['message' => 'Something broke', 'url' => 'https://app.test/cart'], $payload),
        null,
        null,
        null,
    );
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function limitsLogItem(string $channel = 'app', array $overrides = []): array
{
    $config = testConfig(array_replace(['internal_logging' => ['enabled' => false]], $overrides));

    return (new LogItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))
        ->build('error', 'Logged', [], $channel, '2026-11-13T10:00:00+00:00', []);
}

test('an error item cuts a name field over its limit to its first characters, with no suffix', function (string $key, int $max): void {
    $over = limitsErrorItem([$key => str_repeat('é', $max).'tail']);
    $atLimit = limitsErrorItem([$key => str_repeat('é', $max)]);

    expect($over[$key])->toBe(str_repeat('é', $max))
        ->and($atLimit[$key])->toBe(str_repeat('é', $max));
})->with([
    'environment' => ['environment', 50],
    'framework' => ['framework', 50],
    'framework_version' => ['framework_version', 50],
]);

test('an error item cuts a console command over its limit, the suffix inside the limit', function (): void {
    $over = limitsErrorItem(context: ErrorContext::provided(isConsole: true, consoleCommand: 'artisan run '.str_repeat('ü', 1_200)));
    $atLimit = 'artisan run '.str_repeat('ü', 1_000 - 12);

    expect(mb_strlen($over['console_command']))->toBe(1_000)
        ->and($over['console_command'])->toStartWith('artisan run üü')
        ->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX)
        ->and(limitsErrorItem(context: ErrorContext::provided(isConsole: true, consoleCommand: $atLimit))['console_command'])
        ->toBe($atLimit);
});

/**
 * The scrub lengthens every secret it redacts, so a command line within the
 * limit as typed can pass it once scrubbed. The cut runs after the scrub, on
 * the text that is sent.
 */
test('a console command that only passes its limit once scrubbed is cut after the scrub', function (): void {
    $command = 'artisan run '.mb_rtrim(str_repeat('--password=x ', 75));

    $payload = limitsErrorItem(context: ErrorContext::provided(isConsole: true, consoleCommand: $command));

    expect(mb_strlen($command))->toBeLessThanOrEqual(1_000)
        ->and(mb_strlen($payload['console_command']))->toBe(1_000)
        ->and($payload['console_command'])->toStartWith('artisan run --password=[REDACTED]')
        ->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX)
        ->not->toContain('password=x');
});

test('an error item whose environment is cut writes one warning naming both names and the limit', function (): void {
    $log = new RecordingDiagnostics;
    $configured = str_repeat('é', 50).'-tail';

    $payload = limitsErrorItem(['environment' => $configured], log: $log);

    expect($payload['environment'])->toBe(str_repeat('é', 50))
        ->and($log->records)->toBe([[
            'level' => 'warning',
            'message' => 'Ranetrace environment name exceeded the endpoint limit and was cut',
            'context' => [
                'configured_environment' => $configured,
                'sent_environment' => str_repeat('é', 50),
                'max_length' => EnvironmentName::MAX_LENGTH,
            ],
        ]]);
});

test('an error item whose environment fits writes no warning', function (): void {
    $log = new RecordingDiagnostics;

    $payload = limitsErrorItem(['environment' => str_repeat('é', 50)], log: $log);

    expect($payload['environment'])->toBe(str_repeat('é', 50))
        ->and($log->records)->toBe([]);
});

test('a diagnostics sink that fails costs the environment warning, never the error item', function (): void {
    $payload = limitsErrorItem(['environment' => str_repeat('a', 60)], log: new RecordingDiagnostics(throws: true));

    expect($payload['environment'])->toBe(str_repeat('a', 50));
});

test('a javascript error cuts a free-text field over its limit, the suffix inside the limit', function (string $field, int $max, string $prefix): void {
    $over = limitsJavaScriptItem([$field => $prefix.str_repeat('ü', $max + 1)]);
    $atLimit = $prefix.str_repeat('ü', $max - mb_strlen($prefix));

    expect(mb_strlen($over[$field]))->toBe($max)
        ->and($over[$field])->toStartWith($prefix.'üü')
        ->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX)
        ->and(limitsJavaScriptItem([$field => $atLimit])[$field])->toBe($atLimit);
})->with([
    'message' => ['message', 2_000, ''],
    'stack' => ['stack', 10_000, ''],
    'url' => ['url', 2_000, 'https://app.test/'],
]);

test('a javascript error cuts a name field over its limit to its first characters, with no suffix', function (string $field, int $max): void {
    expect(limitsJavaScriptItem([$field => str_repeat('ü', $max).'tail'])[$field])->toBe(str_repeat('ü', $max))
        ->and(limitsJavaScriptItem([$field => str_repeat('ü', $max)])[$field])->toBe(str_repeat('ü', $max));
})->with([
    'type' => ['type', 100],
    'filename' => ['filename', 500],
]);

test('a breadcrumb category is cut like a name and its message like free text', function (): void {
    $crumb = static fn (string $category, string $message): array => limitsJavaScriptItem(['breadcrumbs' => [[
        'timestamp' => '2026-11-13T10:00:00+00:00',
        'category' => $category,
        'message' => $message,
        'data' => [],
    ]]])['breadcrumbs'][0];

    $over = $crumb(str_repeat('ü', 100).'tail', str_repeat('ü', 600));
    $atLimit = $crumb(str_repeat('ü', 100), str_repeat('ü', 500));

    expect($over['category'])->toBe(str_repeat('ü', 100))
        ->and(mb_strlen($over['message']))->toBe(500)
        ->and($over['message'])->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX)
        ->and($atLimit['category'])->toBe(str_repeat('ü', 100))
        ->and($atLimit['message'])->toBe(str_repeat('ü', 500));
});

/**
 * A payload that skipped the relay's validation can carry anything here, and
 * the item has always passed such a value through as it came.
 */
test('a breadcrumb category or message that is not a string is passed through uncut', function (): void {
    $crumb = limitsJavaScriptItem(['breadcrumbs' => [['category' => 42, 'message' => ['nested' => str_repeat('ü', 600)]]]])['breadcrumbs'][0];

    expect($crumb['category'])->toBe(42)
        ->and($crumb['message'])->toBe(['nested' => str_repeat('ü', 600)]);
});

/**
 * The relay checks the browser's lengths before the builder scrubs, and every
 * redaction lengthens the text, so a report that passes validation can still
 * reach the builder over a limit. Each of these arrives at the limit with no
 * secret left in what it kept.
 */
test('a javascript error that only passes its limits once scrubbed is cut after the scrub, through the relay', function (): void {
    $config = testConfig([
        'environment' => 'testing',
        'javascript_errors' => ['enabled' => true],
        'internal_logging' => ['enabled' => false],
    ]);
    $buffer = new ArrayBuffer;
    $relay = new Relay($config, $buffer, new SecretScrubber($config, new InternalLogger($config)), new FingerprintGenerator($config), new InternalLogger($config));

    $message = mb_rtrim(str_repeat('password=x ', 180));
    $stack = mb_rtrim(str_repeat('password=x ', 900));
    $url = 'https://app.test/cart?'.implode('&', array_fill(0, 240, 'token=x'));

    $response = $relay->handleRequest(
        ['HTTP_HOST' => 'app.test', 'HTTP_ORIGIN' => 'https://app.test'],
        ['message' => $message, 'stack' => $stack, 'url' => $url],
    );

    $item = $buffer->payloads('javascript_errors')[0];

    expect($response->status)->toBe(200)
        ->and([mb_strlen($message), mb_strlen($stack), mb_strlen($url)])->toBe([1_979, 9_899, 1_941])
        ->and(mb_strlen($item['message']))->toBe(2_000)
        ->and(mb_strlen($item['stack']))->toBe(10_000)
        ->and(mb_strlen($item['url']))->toBe(2_000)
        ->and($item['message'])->toStartWith('password=[REDACTED]')->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX)->not->toContain('password=x')
        ->and($item['stack'])->toStartWith('password=[REDACTED]')->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX)->not->toContain('password=x')
        ->and($item['url'])->toStartWith('https://app.test/cart?token=[REDACTED]')->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX)->not->toContain('token=x');
});

test('a log channel over its limit is cut to its first characters, with no suffix', function (): void {
    expect(limitsLogItem(str_repeat('ü', 255).'tail')['channel'])->toBe(str_repeat('ü', 255))
        ->and(limitsLogItem(str_repeat('ü', 255))['channel'])->toBe(str_repeat('ü', 255));
});

/**
 * One application must not report two spellings of its environment, so the
 * log item, whose endpoint takes any length there, sends the same cut name as
 * the two items whose endpoints refuse a longer one.
 */
test('an overlong environment arrives as the same name in the error, javascript error and log items', function (): void {
    $configured = ['environment' => str_repeat('é', 50).'-staging-eu-west'];

    expect(limitsErrorItem($configured)['environment'])->toBe(str_repeat('é', 50))
        ->and(limitsJavaScriptItem([], $configured)['environment'])->toBe(str_repeat('é', 50))
        ->and(limitsLogItem(overrides: $configured)['extra']['environment'])->toBe(str_repeat('é', 50));
});

test('an environment that is not a scalar keeps each item its own fallback', function (): void {
    $configured = ['environment' => ['production']];

    expect(limitsErrorItem($configured)['environment'])->toBe('')
        ->and(limitsJavaScriptItem([], $configured)['environment'])->toBe('production')
        ->and(limitsLogItem(overrides: $configured)['extra']['environment'])->toBe('');
});
