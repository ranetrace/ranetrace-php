<?php

declare(strict_types=1);

use Monolog\Level;
use Monolog\LogRecord;
use Ranetrace\Php\Contract\WireContract;
use Ranetrace\Php\Errors\ErrorReporter;
use Ranetrace\Php\Events\EventTracker;
use Ranetrace\Php\JavaScript\Relay;
use Ranetrace\Php\Logging\RanetraceHandler;
use Ranetrace\Php\Support\FingerprintGenerator;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;
use Ranetrace\Php\Tests\Contract\DescriptorValidator;
use Ranetrace\Php\Tests\Doubles\ArrayBuffer;

/**
 * The four emitters, each producing one buffered payload through its real
 * capture path.
 *
 * The helpers are local rather than borrowed from the unit tests: those live in
 * `tests/Unit`, and a Pest file only sees functions from files loaded in the
 * same process, which parallel runs do not guarantee.
 *
 * @return array<string, array<string, mixed>>
 */
function contractEmittedPayloads(): array
{
    $config = testConfig([
        'environment' => 'testing',
        'internal_logging' => ['enabled' => false],
        'logging' => ['enabled' => true],
        'javascript_errors' => ['enabled' => true],
    ]);

    $scrubber = new SecretScrubber($config, new InternalLogger($config));
    $fingerprints = new FingerprintGenerator($config);
    $log = new InternalLogger($config);

    $buffer = new ArrayBuffer;

    $reporter = new ErrorReporter($config, $buffer, $scrubber, $log);
    $reporter->setServerContext(['REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'app.test', 'REQUEST_URI' => '/orders/912'], false);
    $reporter->report(new RuntimeException('Something broke'));

    (new EventTracker($config, $buffer, $scrubber, $fingerprints, $log))
        ->track('checkout_completed', ['order_id' => 'ORD-4821', 'total_amount' => 149.95]);

    (new RanetraceHandler($config, $buffer, $scrubber, $log))->handle(new LogRecord(
        new DateTimeImmutable('2026-08-19 09:30:45'),
        'payments',
        Level::Warning,
        'Payment gateway timed out',
        ['order_id' => 'ORD-4821'],
        [],
    ));

    (new Relay($config, $buffer, $scrubber, $fingerprints, $log))->handleRequest(
        ['HTTP_HOST' => 'app.test', 'HTTP_ORIGIN' => 'https://app.test', 'HTTP_USER_AGENT' => 'Test Browser'],
        [
            'message' => "Cannot read properties of undefined (reading 'total')",
            'url' => 'https://app.test/cart',
            'timestamp' => '2026-08-19T09:30:45+00:00',
        ],
    );

    $payloads = [];

    foreach (WireContract::itemTypes() as $type) {
        $payloads[$type] = $buffer->payloads($type)[0] ?? [];
    }

    return $payloads;
}

test('every emitted key is a field the endpoint declares', function (string $type): void {
    $payload = contractEmittedPayloads()[$type];
    $declared = DescriptorValidator::topLevelKeys(WireContract::item($type)['fields']);

    expect($payload)->not->toBe([])
        ->and(array_diff(array_keys($payload), $declared))->toBe([]);
})->with(WireContract::itemTypes());

test('every field the endpoint requires is emitted and not null', function (string $type): void {
    $payload = contractEmittedPayloads()[$type];
    $missing = [];

    foreach (WireContract::item($type)['fields'] as $field => $descriptor) {
        if (str_contains((string) $field, '.') || ($descriptor['required'] ?? false) !== true) {
            continue;
        }

        if (! array_key_exists($field, $payload) || $payload[$field] === null) {
            $missing[] = (string) $field;
        }
    }

    expect($missing)->toBe([]);
})->with(WireContract::itemTypes());

/**
 * The generic pair replaced it, and the endpoint still tolerates the old
 * spelling only for Laravel SDK versions already in production. This SDK
 * emitting it would keep that compatibility branch alive forever.
 */
test('the error payload never carries the legacy laravel_version key', function (): void {
    expect(contractEmittedPayloads()['errors'])
        ->not->toHaveKey('laravel_version')
        ->toHaveKey('framework')
        ->toHaveKey('framework_version');
});
