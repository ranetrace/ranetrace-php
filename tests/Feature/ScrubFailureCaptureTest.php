<?php

declare(strict_types=1);

use Monolog\Logger;
use Ranetrace\Php\Contract\WireContract;
use Ranetrace\Php\Ranetrace;
use Ranetrace\Php\Tests\Contract\DescriptorValidator;
use Ranetrace\Php\Tests\Doubles\FakeHttpClient;

/**
 * A scrub that fails, followed from capture to the request body the API would
 * receive, on a host that turns every PHP warning into an exception the way
 * Laravel and Symfony do.
 *
 * The failure is one a host can cause from its own config: a list of
 * `scrubbing.extra_keys` long enough that PCRE refuses to compile the pattern
 * built from it. PCRE says so with a warning, the host's handler throws it, and
 * what leaves the scrubber is an ErrorException. These tests pin that the
 * capture is still sent, with every string the scrubber could not read
 * replaced by the placeholder and every other field as it was.
 */
function scrubFailureSdk(FakeHttpClient $http, array $overrides = []): Ranetrace
{
    return new Ranetrace(array_replace_recursive([
        'key' => 'test-api-key-12345',
        'buffer_path' => tempDirectory(),
        'flush_on_shutdown' => false,
        'internal_logging' => ['enabled' => false],
        'scrubbing' => ['extra_keys' => uncompilableExtraKeys()],
    ], $overrides))->withHttpClient($http);
}

/**
 * Enough fragments that the pattern built from them is past what PCRE
 * compiles.
 *
 * @return list<string>
 */
function uncompilableExtraKeys(): array
{
    return array_map(static fn (int $number): string => "customer_secret_field_number_{$number}", range(1, 2_000));
}

/**
 * Run $capture under an error handler that throws on every warning.
 */
function underThrowingErrorHandler(Closure $capture): mixed
{
    set_error_handler(static function (int $level, string $message): never {
        throw new ErrorException($message, 0, $level);
    });

    try {
        return $capture();
    } finally {
        restore_error_handler();
    }
}

test('an error whose scrub fails is sent with its free-form strings redacted and the rest intact', function (): void {
    $http = FakeHttpClient::respondingWith(200);
    $sdk = scrubFailureSdk($http);
    $line = __LINE__ + 1;
    $exception = new RuntimeException('Connection refused for password=hunter2');

    underThrowingErrorHandler(fn () => $sdk->report($exception));
    $sdk->flush('errors');

    $item = $http->payload()['errors'][0] ?? [];

    expect($http->requests)->toHaveCount(1)
        ->and($item['message'])->toBe('[REDACTED]')
        ->and($item['trace'])->toBe('[REDACTED]')
        ->and($item['type'])->toBe(RuntimeException::class)
        ->and($item['line'])->toBe($line)
        ->and($item['file'])->toEndWith('ScrubFailureCaptureTest.php')
        ->and($item['frames'])->not->toBeEmpty()
        ->and(json_encode($item))->not->toContain('hunter2')
        ->and(DescriptorValidator::violations(WireContract::item('errors')['fields'], $item, true))->toBe([]);
});

test('a source line the scrubber could not read never leaves with an error', function (): void {
    $http = FakeHttpClient::respondingWith(200);
    $sdk = scrubFailureSdk($http);

    underThrowingErrorHandler(fn () => $sdk->report(new RuntimeException('boom')));
    $sdk->flush('errors');

    $item = $http->payload()['errors'][0] ?? [];
    $sourceLines = array_unique(explode("\n", mb_rtrim((string) $item['context'])));

    expect($sourceLines)->toBe(['[REDACTED]']);
});

test('a log record whose scrub fails is sent with its message redacted and its context scrubbed', function (): void {
    $http = FakeHttpClient::respondingWith(200);
    $sdk = scrubFailureSdk($http, ['logging' => ['enabled' => true]]);
    $logger = new Logger('billing', [$sdk->monologHandler()]);

    underThrowingErrorHandler(fn () => $logger->error('Charge failed for token=tok_live_123', ['order' => 912, 'password' => 'hunter2']));
    $sdk->flush('logs');

    $item = $http->payload()['logs'][0] ?? [];

    expect($http->requests)->toHaveCount(1)
        ->and($item['message'])->toBe('[REDACTED]')
        ->and($item['level'])->toBe('error')
        ->and($item['channel'])->toBe('billing')
        ->and($item['context'])->toBe(['order' => 912, 'password' => '[REDACTED]']);
});

test('a browser error whose scrub fails is accepted and sent with its message redacted', function (): void {
    $http = FakeHttpClient::respondingWith(200);
    $sdk = scrubFailureSdk($http, ['javascript_errors' => ['enabled' => true]]);

    $response = underThrowingErrorHandler(fn () => $sdk->relay()->handleRequest([], [
        'message' => 'Login failed for token=abc123',
        'type' => 'TypeError',
        'url' => 'https://example.test/checkout',
    ]));
    $sdk->flush('javascript_errors');

    $item = $http->payload()['javascript_errors'][0] ?? [];

    expect($response->status)->toBe(200)
        ->and($http->requests)->toHaveCount(1)
        ->and($item['message'])->toBe('[REDACTED]')
        ->and($item['type'])->toBe('TypeError')
        ->and($item['url'])->toBe('https://example.test/checkout');
});
