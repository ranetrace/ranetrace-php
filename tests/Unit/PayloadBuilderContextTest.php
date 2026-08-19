<?php

declare(strict_types=1);

use Ranetrace\Php\Errors\ErrorContext;
use Ranetrace\Php\Errors\PayloadBuilder;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;

/**
 * The framework-adapter half of the shared error builder.
 *
 * `ranetrace/ranetrace-laravel` does not read a superglobal: it states what its
 * `Request` observed and what its ROUTER says is secret-bearing, and this
 * builder does the shaping. These tests drive that seam directly, because the
 * plain-PHP reporter can never reach it — it has no router to resolve a path
 * secret from and no clock but its own.
 */

/**
 * @param  array<string, mixed>  $overrides
 */
function contextBuilder(array $overrides = []): PayloadBuilder
{
    $config = testConfig(array_replace_recursive(
        ['internal_logging' => ['enabled' => false]],
        $overrides,
    ));

    return new PayloadBuilder($config, new SecretScrubber($config, new InternalLogger($config)), new InternalLogger($config));
}

test('a host that states its own request has that request shaped, not a superglobal', function (): void {
    $payload = contextBuilder()->build(new RuntimeException('Something broke'), ErrorContext::provided(
        isConsole: false,
        headers: ['host' => ['app.test'], 'user-agent' => ['Mozilla/5.0'], 'cookie' => ['session=abc']],
        url: 'https://app.test/orders/42?api_key=sk-live',
        method: 'post',
    ));

    expect($payload['headers'])->toBe([
        'host' => ['app.test'],
        'user-agent' => ['Mozilla/5.0'],
        'cookie' => ['***'],
    ])
        ->and($payload['url'])->toBe('https://app.test/orders/42?api_key=[REDACTED]')
        ->and($payload['method'])->toBe('POST')
        ->and($payload['is_console'])->toBeFalse();
});

/**
 * The client IP chain is PII, and no IP leaves the host. It is masked like any
 * other header the allowlist does not name, while the (non-PII) proto header
 * beside it stays plaintext.
 */
test('the client IP chain is masked rather than captured', function (): void {
    $payload = contextBuilder()->build(new RuntimeException('Something broke'), ErrorContext::provided(
        isConsole: false,
        headers: [
            'x-forwarded-for' => ['203.0.113.7, 198.51.100.2'],
            'x-forwarded-proto' => ['https'],
        ],
    ));

    expect($payload['headers']['x-forwarded-for'])->toBe(['***'])
        ->and($payload['headers']['x-forwarded-proto'])->toBe(['https']);
});

/**
 * A path segment carries no marker saying "this is a token", so the host that
 * has a router resolves the values and this builder redacts them. Nothing else
 * about the URL is rewritten.
 */
test('the path segment values the host declared secret are redacted from the URL', function (): void {
    $payload = contextBuilder()->build(new RuntimeException('Something broke'), ErrorContext::provided(
        isConsole: false,
        url: 'http://app.test/reset-password/live-reset-token-xyz789?page=2',
        sensitivePathValues: ['live-reset-token-xyz789'],
    ));

    expect($payload['url'])->toBe('http://app.test/reset-password/[REDACTED]?page=2');
});

/**
 * The Referer describes a request that is NOT the one being reported, so its
 * secret-bearing segments have to be resolved per URL rather than reused from
 * the current route.
 */
test('a referer is redacted from the path values the host resolves for that url', function (): void {
    $asked = [];

    $payload = contextBuilder()->build(new RuntimeException('Something broke'), ErrorContext::provided(
        isConsole: false,
        headers: ['referer' => ['http://app.test/invitations/invite-token-abc?token=live']],
        url: 'http://app.test/dashboard',
        sensitivePathValues: ['not-the-referers-secret'],
        refererPathValues: function (string $url) use (&$asked): array {
            $asked[] = $url;

            return ['invite-token-abc'];
        },
    ));

    expect($payload['headers']['referer'])->toBe(['http://app.test/invitations/[REDACTED]?token=[REDACTED]'])
        ->and($asked)->toBe(['http://app.test/invitations/invite-token-abc?token=live']);
});

test('a host that pins the capture time gets its value, not the builder clock', function (): void {
    $payload = contextBuilder()->build(new RuntimeException('Something broke'), ErrorContext::provided(
        isConsole: true,
        timestamp: '2026-08-19T09:30:45+00:00',
    ));

    expect($payload['timestamp'])->toBe('2026-08-19T09:30:45+00:00');
});

test('a host that states its console command line has it scrubbed and bounded', function (): void {
    $payload = contextBuilder()->build(new RuntimeException('Something broke'), ErrorContext::provided(
        isConsole: true,
        consoleCommand: 'artisan queue:work --token=sk-live-secret',
        consoleArguments: ['artisan', 'queue:work', '--token=sk-live-secret'],
    ));

    expect($payload['console_command'])->toBe('artisan queue:work --token=[REDACTED]')
        ->and($payload['console_arguments'])->toBe(['artisan', 'queue:work', '--token=[REDACTED]'])
        ->and($payload['headers'])->toBeNull()
        ->and($payload['url'])->toBeNull();
});

/**
 * A minified or generated source line would otherwise bloat the item on its
 * own. The suffix sits OUTSIDE the cap here, unlike every other truncated
 * field: the context field has no cap of its own, so the fifteen-character
 * overshoot per line is harmless and this is what both SDKs have always sent.
 */
test('an over-long source line is capped inside the preview and keeps its newline', function (): void {
    $file = tempDirectory().'/minified.php';
    file_put_contents($file, "short line\n".str_repeat('x', 5_000)."\nlast line\n");

    $exception = new Exception('Something broke');
    (new ReflectionProperty(Exception::class, 'file'))->setValue($exception, $file);
    (new ReflectionProperty(Exception::class, 'line'))->setValue($exception, 2);

    $lines = explode("\n", (string) contextBuilder()->build($exception, ErrorContext::provided(isConsole: true))['context']);

    expect($lines[0])->toBe('short line')
        ->and(mb_strlen($lines[1]))->toBe(2_000 + mb_strlen(PayloadBuilder::TRUNCATION_SUFFIX))
        ->and($lines[1])->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX)
        ->and($lines[2])->toBe('last line');
});
