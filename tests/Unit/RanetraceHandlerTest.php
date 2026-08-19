<?php

declare(strict_types=1);

use Monolog\Level;
use Monolog\LogRecord;
use Ranetrace\Php\Logging\RanetraceHandler;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\ItemByteBudget;
use Ranetrace\Php\Support\SecretScrubber;
use Ranetrace\Php\Tests\Doubles\ArrayBuffer;

/**
 * @param  array<string, mixed>  $overrides
 */
function logHandler(
    ArrayBuffer $buffer,
    array $overrides = [],
    int|string|Level|null $level = null,
): RanetraceHandler {
    $config = testConfig(array_replace_recursive([
        'environment' => 'staging',
        'internal_logging' => ['enabled' => false],
        'logging' => ['enabled' => true],
    ], $overrides));

    return new RanetraceHandler($config, $buffer, new SecretScrubber($config, new InternalLogger($config)), new InternalLogger($config), $level);
}

/**
 * @param  array<string, mixed>  $context
 * @param  array<string, mixed>  $extra
 */
function logRecord(
    string $message = 'Payment gateway timed out',
    Level $level = Level::Warning,
    array $context = [],
    array $extra = [],
    string $channel = 'app',
): LogRecord {
    return new LogRecord(new DateTimeImmutable('2026-08-06 09:30:00'), $channel, $level, $message, $context, $extra);
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<int, array<string, mixed>>
 */
function handledPayloads(LogRecord $record, array $overrides = [], int|string|Level|null $level = null): array
{
    $buffer = new ArrayBuffer;

    logHandler($buffer, $overrides, $level)->handle($record);

    return $buffer->payloads('logs');
}

test('it buffers exactly the six keys the API accepts', function (): void {
    $payload = handledPayloads(logRecord())[0];

    expect(array_keys($payload))->toEqualCanonicalizing([
        'level',
        'message',
        'context',
        'channel',
        'timestamp',
        'extra',
    ]);
});

test('it maps the Monolog record onto the wire fields', function (): void {
    $payload = handledPayloads(logRecord(
        message: 'Payment gateway timed out',
        level: Level::Error,
        context: ['order_id' => 17],
        channel: 'billing',
    ))[0];

    expect($payload['level'])->toBe('error')
        ->and($payload['message'])->toBe('Payment gateway timed out')
        ->and($payload['context'])->toBe(['order_id' => 17])
        ->and($payload['channel'])->toBe('billing')
        ->and($payload['timestamp'])->toBe((new DateTimeImmutable('2026-08-06 09:30:00'))->format('c'));
});

test('it lowercases every PSR-3 severity', function (Level $level, string $expected): void {
    $payload = handledPayloads(logRecord(level: $level), level: Level::Debug)[0];

    expect($payload['level'])->toBe($expected);
})->with([
    [Level::Debug, 'debug'],
    [Level::Info, 'info'],
    [Level::Notice, 'notice'],
    [Level::Warning, 'warning'],
    [Level::Error, 'error'],
    [Level::Critical, 'critical'],
    [Level::Alert, 'alert'],
    [Level::Emergency, 'emergency'],
]);

test('it captures nothing below the configured default of notice', function (): void {
    expect(handledPayloads(logRecord(level: Level::Info)))->toBe([])
        ->and(handledPayloads(logRecord(level: Level::Debug)))->toBe([])
        ->and(handledPayloads(logRecord(level: Level::Notice)))->toHaveCount(1);
});

test('it honours an explicitly passed minimum level over the configured one', function (): void {
    expect(handledPayloads(logRecord(level: Level::Warning), level: Level::Error))->toBe([])
        ->and(handledPayloads(logRecord(level: Level::Error), level: Level::Error))->toHaveCount(1)
        ->and(handledPayloads(logRecord(level: Level::Debug), level: 'debug'))->toHaveCount(1);
});

test('it skips the channels the host excluded', function (): void {
    $overrides = ['logging' => ['excluded_channels' => ['noisy', 'deploy']]];

    expect(handledPayloads(logRecord(channel: 'noisy'), $overrides))->toBe([])
        ->and(handledPayloads(logRecord(channel: 'app'), $overrides))->toHaveCount(1);
});

test('it attaches the environment and the runtime to extra', function (): void {
    $payload = handledPayloads(logRecord(extra: ['request_id' => 'abc']))[0];

    expect($payload['extra'])->toBe([
        'request_id' => 'abc',
        'environment' => 'staging',
        'php_version' => PHP_VERSION,
    ]);
});

test('it names the framework in extra only when the host configured one', function (): void {
    $payload = handledPayloads(logRecord(), [
        'framework' => 'symfony',
        'framework_version' => '7.1.2',
    ])[0];

    expect($payload['extra'])->toBe([
        'environment' => 'staging',
        'php_version' => PHP_VERSION,
        'framework' => 'symfony',
        'framework_version' => '7.1.2',
    ]);
});

test('it scrubs secrets out of the message before truncating it', function (): void {
    $payload = handledPayloads(logRecord(message: 'Retrying with api_key=live-abc123 after failure'))[0];

    expect($payload['message'])->toBe('Retrying with api_key=[REDACTED] after failure');
});

test('it truncates the message with the suffix counted inside the limit', function (): void {
    $payload = handledPayloads(logRecord(message: str_repeat('a', 60_000)))[0];

    expect(mb_strlen($payload['message']))->toBe(50_000)
        ->and($payload['message'])->toEndWith('... (truncated)');
});

test('it sanitizes and scrubs the context', function (): void {
    $payload = handledPayloads(logRecord(context: [
        'password' => 'hunter2',
        'callback' => static fn (): int => 1,
        'endpoint' => 'https://api.example.test/v1?token=abc123',
    ]))[0];

    expect($payload['context'])->toBe([
        'password' => '[REDACTED]',
        'callback' => '[Closure]',
        'endpoint' => 'https://api.example.test/v1?token=[REDACTED]',
    ]);
});

test('it replaces an oversized context wholesale, since partial JSON is invalid', function (): void {
    $payload = handledPayloads(logRecord(context: ['blob' => str_repeat('a', 60_000)]))[0];

    expect($payload['context'])->toBe(['_truncated' => 'Context exceeded 50KB limit and was removed']);
});

test('it replaces an oversized extra wholesale but keeps the environment trio', function (): void {
    $payload = handledPayloads(logRecord(extra: ['blob' => str_repeat('a', 20_000)]))[0];

    expect($payload['extra'])->toBe([
        '_truncated' => 'Extra data exceeded 10KB limit and was removed',
        'environment' => 'staging',
        'php_version' => PHP_VERSION,
    ]);
});

test('it captures nothing while logging is switched off', function (array $overrides): void {
    expect(handledPayloads(logRecord(), $overrides))->toBe([]);
})->with([
    'globally disabled' => [['enabled' => false]],
    'feature disabled' => [['logging' => ['enabled' => false]]],
    'no API key' => [['key' => '']],
]);

test('it stays silent when the buffer refuses the write', function (): void {
    $buffer = new ArrayBuffer;
    $buffer->rejectWrites = true;

    logHandler($buffer)->handle(logRecord());

    expect($buffer->items)->toBe([]);
});

test('it never throws back into the call site that logged', function (): void {
    $buffer = new class extends ArrayBuffer
    {
        public function addItem(string $type, array $data): bool
        {
            throw new RuntimeException('Buffer exploded');
        }
    };

    logHandler($buffer)->handle(logRecord());

    expect($buffer->items)->toBe([]);
});

test('a log record over the per-item byte budget is shrunk before it is buffered', function (): void {
    // The message cap counts characters, so 40,000 three-byte characters clear
    // it and still weigh 120 KB. The byte budget at the buffer handoff is what
    // catches that.
    $payload = handledPayloads(logRecord(str_repeat('→', 40_000)))[0];

    expect(array_keys($payload))->toEqualCanonicalizing(['level', 'message', 'context', 'channel', 'timestamp', 'extra'])
        ->and($payload['message'])->toEndWith('... (truncated)')
        ->and($payload)->not->toHaveKey('_truncated')
        ->and(mb_strlen((string) json_encode($payload), '8bit'))->toBeLessThanOrEqual(ItemByteBudget::MAX_ITEM_BYTES);
});
