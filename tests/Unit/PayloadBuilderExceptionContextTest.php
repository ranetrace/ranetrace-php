<?php

declare(strict_types=1);

use Ranetrace\Php\Errors\ErrorContext;
use Ranetrace\Php\Errors\PayloadBuilder;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;

/**
 * `exception_context` is read from the throwable itself, the way Laravel's log
 * reporter reads it, so both SDKs get it from this one builder. The backend
 * fails the whole batch on a context past 100 keys, 5 levels or 16,384 bytes,
 * so these tests pin the tighter bounds the SDK holds it to.
 */
function exceptionContextBuilder(): PayloadBuilder
{
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    return new PayloadBuilder($config, new SecretScrubber($config, new InternalLogger($config)), new InternalLogger($config));
}

/**
 * @return array<string, mixed>
 */
function exceptionContextPayload(Throwable $throwable, ?ErrorContext $context = null): array
{
    return exceptionContextBuilder()->build($throwable, $context ?? ErrorContext::provided(isConsole: true));
}

/**
 * A throwable whose public `context()` returns whatever the callback does, or
 * throws whatever it throws.
 */
function throwableWithContext(Closure $context): RuntimeException
{
    return new class('Something broke', $context) extends RuntimeException
    {
        public function __construct(string $message, private readonly Closure $contextFactory)
        {
            parent::__construct($message);
        }

        public function context(): mixed
        {
            return ($this->contextFactory)();
        }
    };
}

test('the context a throwable carries is forwarded as exception_context', function (): void {
    $payload = exceptionContextPayload(throwableWithContext(static fn (): array => ['user_id' => 42, 'price' => 'price_123']));

    expect($payload['exception_context'])->toBe(['user_id' => 42, 'price' => 'price_123']);
});

test('exception_context is present and null when the throwable has no context method', function (): void {
    $payload = exceptionContextPayload(new RuntimeException('Something broke'));

    expect($payload)->toHaveKey('exception_context')
        ->and($payload['exception_context'])->toBeNull();
});

test('a context method that is not public is not called', function (): void {
    $throwable = new class('Something broke') extends RuntimeException
    {
        public bool $called = false;

        protected function context(): array
        {
            $this->called = true;

            return ['user_id' => 42];
        }
    };

    expect(exceptionContextPayload($throwable)['exception_context'])->toBeNull()
        ->and($throwable->called)->toBeFalse();
});

test('a context that is empty or not an array is sent as null', function (mixed $value): void {
    expect(exceptionContextPayload(throwableWithContext(static fn (): mixed => $value))['exception_context'])->toBeNull();
})->with([
    'an empty array' => [[]],
    'a string' => ['user 42'],
    'an integer' => [42],
    'null' => [null],
    'an object' => [new ArrayObject(['user_id' => 42])],
]);

test('a context method that throws still lets the error be captured, without a context', function (): void {
    $payload = exceptionContextPayload(throwableWithContext(static fn (): never => throw new LogicException('context broke')));

    expect($payload['exception_context'])->toBeNull()
        ->and($payload['message'])->toBe('Something broke')
        ->and($payload['type'])->not->toBe(LogicException::class);
});

test('a host path resolver that throws while the context is scrubbed costs neither the error nor the context', function (): void {
    $payload = exceptionContextPayload(
        throwableWithContext(static fn (): array => ['next' => 'https://app.test/reset/abc?page=2']),
        ErrorContext::provided(
            isConsole: false,
            refererPathValues: static fn (string $url): never => throw new LogicException('router broke'),
        ),
    );

    expect($payload['exception_context'])->toBe(['next' => 'https://app.test/reset/abc?page=2'])
        ->and($payload['message'])->toBe('Something broke');
});

test('secret keys and secrets inside URL values are masked', function (): void {
    $payload = exceptionContextPayload(throwableWithContext(static fn (): array => [
        'user_id' => 42,
        'password' => 'hunter2',
        'gateway' => ['api_key' => 'sk-live-123', 'region' => 'eu'],
        'callback' => 'https://app.test/hook?token=live-token&page=2',
    ]));

    expect($payload['exception_context'])->toBe([
        'user_id' => 42,
        'password' => '[REDACTED]',
        'gateway' => ['api_key' => '[REDACTED]', 'region' => 'eu'],
        'callback' => 'https://app.test/hook?token=[REDACTED]&page=2',
    ]);
});

test('the path segments the host resolves as secret are redacted from URL values', function (): void {
    $payload = exceptionContextPayload(
        throwableWithContext(static fn (): array => ['next' => 'https://app.test/reset/live-reset-token']),
        ErrorContext::provided(
            isConsole: false,
            refererPathValues: static fn (string $url): array => ['live-reset-token'],
        ),
    );

    expect($payload['exception_context'])->toBe(['next' => 'https://app.test/reset/[REDACTED]']);
});

test('objects, closures and resources are flattened the way other captured data is', function (): void {
    $resource = fopen('php://memory', 'r');

    $payload = exceptionContextPayload(throwableWithContext(static fn (): array => [
        'order' => new class implements JsonSerializable
        {
            public function jsonSerialize(): array
            {
                return ['id' => 912, 'total' => 149.95];
            }
        },
        'plain' => new stdClass,
        'callback' => static fn (): bool => true,
        'stream' => $resource,
    ]));

    fclose($resource);

    expect($payload['exception_context'])->toBe([
        'order' => ['id' => 912, 'total' => 149.95],
        'plain' => '[Object: stdClass]',
        'callback' => '[Closure]',
        'stream' => '[Resource: stream]',
    ]);
});

test('a context of more than fifty keys keeps its first fifty', function (): void {
    $context = [];

    for ($index = 1; $index <= 51; $index++) {
        $context["key_{$index}"] = $index;
    }

    $sent = exceptionContextPayload(throwableWithContext(static fn (): array => $context))['exception_context'];

    expect($sent)->toHaveCount(50)
        ->and(array_key_first($sent))->toBe('key_1')
        ->and(array_key_last($sent))->toBe('key_50');
});

test('a context three levels deep is sent whole', function (): void {
    $context = ['a' => ['b' => ['c' => 1, 'd' => 'x']], 'e' => []];

    expect(exceptionContextPayload(throwableWithContext(static fn (): array => $context))['exception_context'])->toBe($context);
});

test('a value nested past the third level is replaced by the depth marker', function (): void {
    $payload = exceptionContextPayload(throwableWithContext(static fn (): array => [
        'a' => ['b' => ['c' => ['d' => 1], 'e' => 'kept', 'g' => []]],
        'f' => 2,
    ]));

    expect($payload['exception_context'])->toBe([
        'a' => ['b' => ['c' => '[Max depth exceeded]', 'e' => 'kept', 'g' => '[Max depth exceeded]']],
        'f' => 2,
    ]);
});

test('a long string value is truncated with the suffix counted inside the cap', function (): void {
    $payload = exceptionContextPayload(throwableWithContext(static fn (): array => [
        'query' => str_repeat('a', 2_000),
        'nested' => ['note' => str_repeat('b', 2_000)],
    ]));

    expect($payload['exception_context']['query'])->toHaveLength(500)->toEndWith('... (truncated)')
        ->and($payload['exception_context']['nested']['note'])->toHaveLength(500)->toEndWith('... (truncated)');
});

test('a context over the byte cap drops trailing keys until it fits', function (): void {
    $context = [];

    for ($index = 1; $index <= 40; $index++) {
        $context["key_{$index}"] = str_repeat('x', 400);
    }

    $sent = exceptionContextPayload(throwableWithContext(static fn (): array => $context))['exception_context'];

    expect(mb_strlen((string) json_encode($sent), '8bit'))->toBeLessThanOrEqual(8_192)
        ->and(count($sent))->toBeGreaterThan(1)
        ->and($sent)->toBe(array_slice($context, 0, count($sent)))
        ->and(mb_strlen((string) json_encode(array_slice($context, 0, count($sent) + 1)), '8bit'))->toBeGreaterThan(8_192);
});

test('a context whose first key alone is over the byte cap is sent as null', function (): void {
    $payload = exceptionContextPayload(throwableWithContext(static fn (): array => [
        'ids' => range(1_000_000, 1_002_000),
        'small' => 1,
    ]));

    expect($payload['exception_context'])->toBeNull()
        ->and($payload['message'])->toBe('Something broke');
});

test('a float JSON cannot spell is sent as its string spelling rather than costing the context', function (float $value, string $spelled): void {
    $payload = exceptionContextPayload(throwableWithContext(static fn (): array => ['value' => $value, 'kept' => 1]));

    expect($payload['exception_context'])->toBe(['value' => $spelled, 'kept' => 1]);
})->with([
    'infinity' => [INF, 'INF'],
    'negative infinity' => [-INF, '-INF'],
    'not a number' => [NAN, 'NAN'],
]);

test('invalid UTF-8 in a context key or value is replaced rather than costing the context', function (): void {
    $payload = exceptionContextPayload(throwableWithContext(static fn (): array => [
        "column\xB1" => ['value' => "\xB1\x31"],
    ]));

    expect($payload['exception_context'])->toBe(["column\u{FFFD}" => ['value' => "\u{FFFD}1"]]);
});

test('a context string of invalid bytes past the string cap is cut inside the cap', function (): void {
    $value = exceptionContextPayload(throwableWithContext(static fn (): array => [
        'value' => str_repeat("\xB1", 600),
    ]))['exception_context']['value'];

    expect(mb_strlen($value))->toBe(500)
        ->and(mb_check_encoding($value, 'UTF-8'))->toBeTrue()
        ->and($value)->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX);
});

test('a list context is sent as a list', function (): void {
    expect(exceptionContextPayload(throwableWithContext(static fn (): array => [42, 'price_123']))['exception_context'])
        ->toBe([42, 'price_123']);
});
