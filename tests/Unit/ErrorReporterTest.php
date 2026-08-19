<?php

declare(strict_types=1);

use Ranetrace\Php\Errors\ErrorReporter;
use Ranetrace\Php\Errors\PayloadBuilder;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;
use Ranetrace\Php\Tests\Doubles\ArrayBuffer;

/**
 * The exact field set the API accepts. A missing or extra key is a 422 for the
 * whole batch, so the tests pin the key set itself, not just the values.
 *
 * @return array<int, string>
 */
function errorPayloadKeys(): array
{
    return [
        'message',
        'file',
        'line',
        'type',
        'environment',
        'trace',
        'headers',
        'context',
        'highlight_line',
        'user',
        'timestamp',
        'url',
        'method',
        'php_version',
        'framework',
        'framework_version',
        'is_console',
        'console_command',
        'console_arguments',
    ];
}

/**
 * @param  array<string, mixed>  $overrides
 */
function errorReporter(ArrayBuffer $buffer, array $overrides = []): ErrorReporter
{
    $config = testConfig(array_replace_recursive(
        ['internal_logging' => ['enabled' => false]],
        $overrides,
    ));

    return new ErrorReporter($config, $buffer, new SecretScrubber($config, new InternalLogger($config)), new InternalLogger($config));
}

/**
 * An exception pointing at a file and line of our choosing, so the source
 * preview, the path handling and the self-protection guard can be exercised
 * without arranging for a real throw from that exact location.
 */
function exceptionAt(string $file, int $line, string $message = 'Something broke'): Exception
{
    $exception = new Exception($message);

    (new ReflectionProperty(Exception::class, 'file'))->setValue($exception, $file);
    (new ReflectionProperty(Exception::class, 'line'))->setValue($exception, $line);

    return $exception;
}

/**
 * A file of numbered lines, for the source-preview tests.
 */
function sourceFile(int $lines = 20, string $indent = ''): string
{
    $path = tempDirectory().'/source.php';
    $content = '';

    for ($number = 1; $number <= $lines; $number++) {
        $content .= $indent.'line '.$number."\n";
    }

    file_put_contents($path, $content);

    return $path;
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function reportedPayload(Throwable $throwable, array $overrides = [], ?array $server = null, bool $isConsole = true): array
{
    $buffer = new ArrayBuffer;
    $reporter = errorReporter($buffer, $overrides);
    $reporter->setServerContext($server ?? [], $isConsole);
    $reporter->report($throwable);

    return $buffer->payloads('errors')[0] ?? [];
}

test('it buffers exactly the nineteen keys the API accepts', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'));

    expect(array_keys($payload))->toEqualCanonicalizing(errorPayloadKeys());
});

test('it captures the throwable identity, the environment and the runtime', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), [
        'environment' => 'staging',
        'framework' => 'slim',
        'framework_version' => '4.12.0',
    ]);

    expect($payload['message'])->toBe('Something broke')
        ->and($payload['type'])->toBe(RuntimeException::class)
        ->and($payload['environment'])->toBe('staging')
        ->and($payload['framework'])->toBe('slim')
        ->and($payload['framework_version'])->toBe('4.12.0')
        ->and($payload['php_version'])->toBe(PHP_VERSION)
        ->and($payload['line'])->toBeInt()
        ->and($payload['trace'])->toBeString();
});

test('it always sends the framework keys, null when the host did not name one', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'));

    expect($payload)->toHaveKey('framework')
        ->and($payload)->toHaveKey('framework_version')
        ->and($payload['framework'])->toBeNull()
        ->and($payload['framework_version'])->toBeNull();
});

test('it stamps the timestamp as ISO 8601', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'));

    expect($payload['timestamp'])->toMatch('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/');
});

test('it scrubs secrets out of the message before truncating it', function (): void {
    $payload = reportedPayload(new RuntimeException('Connection failed with password=hunter2 for user'));

    expect($payload['message'])->toBe('Connection failed with password=[REDACTED] for user');
});

test('it truncates the message with the suffix counted inside the limit', function (): void {
    $payload = reportedPayload(new RuntimeException(str_repeat('a', 12_000)));

    expect(mb_strlen($payload['message']))->toBe(10_000)
        ->and($payload['message'])->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX);
});

test('it truncates the trace with the suffix counted inside the limit', function (): void {
    $deep = function (int $depth) use (&$deep): void {
        if ($depth === 0) {
            throw new RuntimeException('Deep');
        }

        $deep($depth - 1);
    };

    try {
        $deep(200);
    } catch (RuntimeException $exception) {
        $payload = reportedPayload($exception);
    }

    expect(mb_strlen($payload['trace']))->toBe(5_000)
        ->and($payload['trace'])->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX);
});

test('it reports the file relative to the configured project root', function (): void {
    $root = tempDirectory();

    $payload = reportedPayload(
        exceptionAt($root.'/app/Http/Controllers/OrderController.php', 42),
        ['project_root' => $root],
    );

    expect($payload['file'])->toBe('app/Http/Controllers/OrderController.php')
        ->and($payload['line'])->toBe(42);
});

test('it left-truncates a file path longer than the cap, keeping the tail', function (): void {
    $root = tempDirectory();
    $relative = str_repeat('nested/', 100).'Deep.php';

    $payload = reportedPayload(
        exceptionAt($root.'/'.$relative, 7),
        ['project_root' => $root],
    );

    expect(mb_strlen($payload['file']))->toBe(500)
        ->and($payload['file'])->toEndWith('/Deep.php')
        ->and($relative)->toEndWith($payload['file']);
});

test('it previews eleven source lines around the failure and points at the failing one', function (): void {
    $file = sourceFile(20);

    $payload = reportedPayload(exceptionAt($file, 10));

    expect(explode("\n", mb_rtrim($payload['context'], "\n")))->toBe([
        'line 5',
        'line 6',
        'line 7',
        'line 8',
        'line 9',
        'line 10',
        'line 11',
        'line 12',
        'line 13',
        'line 14',
        'line 15',
    ])->and($payload['highlight_line'])->toBe(6);
});

test('it clamps the preview window at the start of the file', function (): void {
    $file = sourceFile(20);

    $payload = reportedPayload(exceptionAt($file, 3));

    $lines = explode("\n", mb_rtrim($payload['context'], "\n"));

    expect($lines[0])->toBe('line 1')
        ->and($lines)->toHaveCount(11)
        ->and($payload['highlight_line'])->toBe(3);
});

test('it strips the indentation the preview lines share', function (): void {
    $file = sourceFile(20, '        ');

    $payload = reportedPayload(exceptionAt($file, 10));

    expect(explode("\n", $payload['context'])[0])->toBe('line 5');
});

test('it sends no preview when the source file cannot be read', function (): void {
    $payload = reportedPayload(exceptionAt('/nonexistent/Missing.php', 10));

    expect($payload['context'])->toBeNull()
        ->and($payload['highlight_line'])->toBeNull();
});

test('it masks every request header that is not on the allowlist', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), server: [
        'HTTP_HOST' => 'example.test',
        'HTTP_USER_AGENT' => 'Mozilla/5.0',
        'HTTP_AUTHORIZATION' => 'Bearer sk-live-secret',
        'HTTP_COOKIE' => 'session=abc',
        'CONTENT_TYPE' => 'application/json',
        'CONTENT_LENGTH' => '42',
        'REQUEST_METHOD' => 'GET',
    ], isConsole: false);

    expect($payload['headers'])->toBe([
        'host' => ['example.test'],
        'user-agent' => ['Mozilla/5.0'],
        'authorization' => ['***'],
        'cookie' => ['***'],
        'content-type' => ['application/json'],
        'content-length' => ['42'],
    ]);
});

test('it caps the header count at fifty', function (): void {
    $server = ['REQUEST_METHOD' => 'GET'];

    for ($index = 1; $index <= 60; $index++) {
        $server['HTTP_X_CUSTOM_'.$index] = 'value';
    }

    $payload = reportedPayload(new RuntimeException('Something broke'), server: $server, isConsole: false);

    expect($payload['headers'])->toHaveCount(50);
});

test('it truncates a header value at five hundred characters', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), server: [
        'HTTP_USER_AGENT' => str_repeat('a', 900),
    ], isConsole: false);

    expect(mb_strlen($payload['headers']['user-agent'][0]))->toBe(500)
        ->and($payload['headers']['user-agent'][0])->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX);
});

test('it scrubs the referer, which can carry a reset token', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), server: [
        'HTTP_REFERER' => 'https://example.test/reset?token=abc123&page=2',
    ], isConsole: false);

    expect($payload['headers']['referer'])->toBe(['https://example.test/reset?token=[REDACTED]&page=2']);
});

test('it sends null headers rather than an empty array, which JSON would encode as a list', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), server: [
        'REQUEST_METHOD' => 'GET',
    ], isConsole: false);

    expect($payload['headers'])->toBeNull();
});

test('it builds the request URL from the server context and scrubs its query', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), server: [
        'HTTPS' => 'on',
        'HTTP_HOST' => 'example.test',
        'REQUEST_URI' => '/orders?api_key=live-secret&page=2',
        'REQUEST_METHOD' => 'post',
    ], isConsole: false);

    expect($payload['url'])->toBe('https://example.test/orders?api_key=[REDACTED]&page=2')
        ->and($payload['method'])->toBe('POST')
        ->and($payload['is_console'])->toBeFalse();
});

test('it treats an HTTPS value of off as plain http', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), server: [
        'HTTPS' => 'off',
        'HTTP_HOST' => 'example.test',
        'REQUEST_URI' => '/orders',
    ], isConsole: false);

    expect($payload['url'])->toBe('http://example.test/orders');
});

test('it truncates the URL at two thousand characters', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), server: [
        'HTTP_HOST' => 'example.test',
        'REQUEST_URI' => '/'.str_repeat('a', 2_500),
    ], isConsole: false);

    expect(mb_strlen($payload['url']))->toBe(2_000)
        ->and($payload['url'])->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX);
});

test('it nulls the console fields on a request', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), server: [
        'HTTP_HOST' => 'example.test',
        'REQUEST_URI' => '/orders',
        'REQUEST_METHOD' => 'GET',
        'argv' => ['worker'],
    ], isConsole: false);

    expect($payload['is_console'])->toBeFalse()
        ->and($payload['console_command'])->toBeNull()
        ->and($payload['console_arguments'])->toBeNull();
});

test('it nulls the request fields on the command line', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), server: [
        'HTTP_HOST' => 'example.test',
        'REQUEST_URI' => '/orders',
        'REQUEST_METHOD' => 'GET',
    ]);

    expect($payload['is_console'])->toBeTrue()
        ->and($payload['headers'])->toBeNull()
        ->and($payload['url'])->toBeNull()
        ->and($payload['method'])->toBeNull();
});

test('it captures the scrubbed command line on the command line', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), server: [
        'argv' => ['bin/worker', 'sync', '--token=abc123'],
    ]);

    expect($payload['console_command'])->toBe('bin/worker sync --token=[REDACTED]')
        ->and($payload['console_arguments'])->toBe(['bin/worker', 'sync', '--token=[REDACTED]']);
});

test('it caps the console arguments at fifty items of five hundred characters', function (): void {
    $argv = array_fill(0, 60, 'short');
    $argv[0] = str_repeat('a', 900);

    $payload = reportedPayload(new RuntimeException('Something broke'), server: ['argv' => $argv]);

    expect($payload['console_arguments'])->toHaveCount(50)
        ->and(mb_strlen($payload['console_arguments'][0]))->toBe(500)
        ->and($payload['console_arguments'][0])->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX);
});

test('it reports no console command when the process has no argv', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), server: []);

    expect($payload['console_command'])->toBeNull()
        ->and($payload['console_arguments'])->toBe([]);
});

test('it sends no user when the host configured no resolver', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'));

    expect($payload['user'])->toBeNull();
});

test('it withholds the email until the host opts in, keeping the key present', function (): void {
    $resolver = static fn (): array => ['id' => 42, 'email' => 'jane@example.test'];

    $withheld = reportedPayload(new RuntimeException('Something broke'), ['user_resolver' => $resolver]);
    $captured = reportedPayload(new RuntimeException('Something broke'), [
        'user_resolver' => $resolver,
        'errors' => ['capture_user_email' => true],
    ]);

    expect($withheld['user'])->toBe(['id' => 42, 'email' => null])
        ->and($captured['user'])->toBe(['id' => 42, 'email' => 'jane@example.test']);
});

test('it sends no user when the resolver reports nobody', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), [
        'user_resolver' => static fn (): ?array => null,
    ]);

    expect($payload['user'])->toBeNull();
});

test('it still reports the error when the host user resolver throws', function (): void {
    $payload = reportedPayload(new RuntimeException('Something broke'), [
        'user_resolver' => static fn (): array => throw new LogicException('No auth here'),
    ]);

    expect($payload)->not->toBeEmpty()
        ->and($payload['user'])->toBeNull()
        ->and($payload['message'])->toBe('Something broke');
});

test('it never reports a throwable this SDK itself threw', function (): void {
    $buffer = new ArrayBuffer;
    $reporter = errorReporter($buffer);

    $reporter->report(exceptionAt(dirname(__DIR__, 2).'/src/Errors/ErrorReporter.php', 10));

    expect($buffer->items)->toBe([]);

    // Control: the same reporter still captures a throwable from anywhere else,
    // so the silence above is the guard and not a gate that closed.
    $reporter->report(exceptionAt('/app/src/Importer.php', 10));

    expect($buffer->payloads('errors'))->toHaveCount(1);
});

test('it falls back to the live superglobal and SAPI when no context was set', function (): void {
    $buffer = new ArrayBuffer;

    errorReporter($buffer)->report(new RuntimeException('Something broke'));

    $payload = $buffer->payloads('errors')[0];

    expect($payload['is_console'])->toBeTrue()
        ->and($payload['console_arguments'])->toBe(array_map(strval(...), $_SERVER['argv']))
        ->and($payload['url'])->toBeNull();
});

test('it captures nothing while error tracking is switched off', function (array $overrides): void {
    $buffer = new ArrayBuffer;
    $reporter = errorReporter($buffer, $overrides);

    $reporter->report(new RuntimeException('Something broke'));

    expect($buffer->items)->toBe([]);
})->with([
    'globally disabled' => [['enabled' => false]],
    'feature disabled' => [['errors' => ['enabled' => false]]],
    'no API key' => [['key' => '']],
]);

test('it stays silent when the buffer refuses the write', function (): void {
    $buffer = new ArrayBuffer;
    $buffer->rejectWrites = true;

    $reporter = errorReporter($buffer);

    $reporter->report(new RuntimeException('Something broke'));

    expect($buffer->items)->toBe([]);
});

test('it reports through the exception handler and still calls the one it replaced', function (): void {
    $buffer = new ArrayBuffer;
    $reporter = errorReporter($buffer);
    $exception = new RuntimeException('Uncaught');
    $seenByPrevious = null;

    set_exception_handler(function (Throwable $throwable) use (&$seenByPrevious): void {
        $seenByPrevious = $throwable;
    });

    try {
        $reporter->register();

        $ours = set_exception_handler(null);
        $ours($exception);
    } finally {
        restore_exception_handler();
        restore_exception_handler();
        restore_exception_handler();
    }

    expect($buffer->payloads('errors'))->toHaveCount(1)
        ->and($buffer->payloads('errors')[0]['message'])->toBe('Uncaught')
        ->and($seenByPrevious)->toBe($exception);
});

test('it reports a fatal error the process died on, which no exception handler ever sees', function (): void {
    $buffer = new ArrayBuffer;
    $reporter = errorReporter($buffer);

    $reporter->setServerContext([], isConsole: true);
    $reporter->reportFatalError([
        'type' => E_ERROR,
        'message' => 'Allowed memory size exhausted',
        'file' => '/app/src/Importer.php',
        'line' => 88,
    ]);

    $payload = $buffer->payloads('errors')[0];

    expect($payload['message'])->toBe('Allowed memory size exhausted')
        ->and($payload['type'])->toBe(ErrorException::class)
        ->and($payload['file'])->toBe('/app/src/Importer.php')
        ->and($payload['line'])->toBe(88);
});

test('it leaves non-fatal errors and a clean shutdown alone', function (?array $error): void {
    $buffer = new ArrayBuffer;
    $reporter = errorReporter($buffer);

    $reporter->reportFatalError($error);

    expect($buffer->items)->toBe([]);
})->with([
    'a warning' => [['type' => E_WARNING, 'message' => 'Undefined index', 'file' => '/app/a.php', 'line' => 1]],
    'a deprecation' => [['type' => E_DEPRECATED, 'message' => 'Passing null', 'file' => '/app/a.php', 'line' => 1]],
    'nothing at all' => [null],
]);
