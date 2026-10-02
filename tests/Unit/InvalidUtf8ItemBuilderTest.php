<?php

declare(strict_types=1);

use Ranetrace\Php\Errors\ErrorContext;
use Ranetrace\Php\Errors\PayloadBuilder;
use Ranetrace\Php\Events\EventItemBuilder;
use Ranetrace\Php\JavaScript\ErrorItemBuilder;
use Ranetrace\Php\Logging\LogItemBuilder;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;

/**
 * Every string the shared builders put in an item reaches the wire as valid
 * UTF-8, because one invalid byte fails the JSON encode of its item, or of its
 * whole batch in a host whose buffer does not encode. The bytes are repaired
 * before the caps run, so these tests also pin that each cap still holds on
 * the text that is sent.
 *
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function utf8ErrorItem(Throwable $throwable, ?ErrorContext $context = null, array $overrides = []): array
{
    $config = testConfig(array_replace_recursive(['internal_logging' => ['enabled' => false]], $overrides));
    $log = new InternalLogger($config);

    return (new PayloadBuilder($config, new SecretScrubber($config, $log), $log))
        ->build($throwable, $context ?? ErrorContext::provided(isConsole: true));
}

function utf8ThrowableAt(string $file, int $line, string $message = 'Something broke'): Exception
{
    $exception = new Exception($message);

    (new ReflectionProperty(Exception::class, 'file'))->setValue($exception, $file);
    (new ReflectionProperty(Exception::class, 'line'))->setValue($exception, $line);

    return $exception;
}

/**
 * @param  array<array-key, mixed>  $context
 * @return array<string, mixed>
 */
function utf8LogItem(string $message = 'Logged', array $context = []): array
{
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    return (new LogItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))
        ->build('error', $message, $context, 'app', '2026-10-02T10:00:00+00:00', []);
}

/**
 * @param  array<string, mixed>  $payload
 * @return array<string, mixed>
 */
function utf8JavaScriptItem(array $payload, ?string $userAgent = null): array
{
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    return (new ErrorItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))
        ->build($payload, $userAgent, null, null);
}

test('an error message of invalid bytes past its cap is cut inside the cap', function (): void {
    $message = utf8ErrorItem(new RuntimeException(str_repeat("\xB1", 12_000)))['message'];

    expect(mb_strlen($message))->toBe(10_000)
        ->and(mb_check_encoding($message, 'UTF-8'))->toBeTrue()
        ->and($message)->toStartWith("\u{FFFD}")
        ->and($message)->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX);
});

test('an error message cut at its cap never splits a multibyte character', function (): void {
    $message = utf8ErrorItem(new RuntimeException(str_repeat('é', 12_000)))['message'];

    expect(mb_strlen($message))->toBe(10_000)
        ->and(mb_check_encoding($message, 'UTF-8'))->toBeTrue();
});

test('a header name with an invalid byte is masked under its repaired name', function (): void {
    $headers = utf8ErrorItem(new RuntimeException('Broke'), ErrorContext::provided(
        isConsole: false,
        headers: ["x-custom\xB1" => ['secret'], 'accept' => ['text/html']],
    ))['headers'];

    expect($headers)->toBe(["x-custom\u{FFFD}" => ['***'], 'accept' => ['text/html']]);
});

test('a safe header value of invalid bytes is repaired inside its cap', function (): void {
    $value = utf8ErrorItem(new RuntimeException('Broke'), ErrorContext::provided(
        isConsole: false,
        headers: ['user-agent' => [str_repeat("\xB1", 600)]],
    ))['headers']['user-agent'][0];

    expect(mb_strlen($value))->toBe(500)
        ->and(mb_check_encoding($value, 'UTF-8'))->toBeTrue()
        ->and($value)->toStartWith("\u{FFFD}");
});

test('a url and a method with invalid bytes are repaired, the url inside its cap', function (): void {
    $item = utf8ErrorItem(new RuntimeException('Broke'), ErrorContext::provided(
        isConsole: false,
        url: 'https://example.test/'.str_repeat("\xB1", 2_100),
        method: "get\xB1",
    ));

    expect(mb_strlen($item['url']))->toBe(2_000)
        ->and(mb_check_encoding($item['url'], 'UTF-8'))->toBeTrue()
        ->and($item['url'])->toStartWith("https://example.test/\u{FFFD}")
        ->and($item['method'])->toBe("GET\u{FFFD}");
});

test('a file path with invalid bytes is repaired inside its cap', function (): void {
    $file = utf8ErrorItem(utf8ThrowableAt('/outside/'.str_repeat("\xB1", 600).'.php', 3))['file'];

    expect(mb_strlen($file))->toBe(500)
        ->and(mb_check_encoding($file, 'UTF-8'))->toBeTrue()
        ->and($file)->toEndWith("\u{FFFD}.php");
});

test('source lines saved in latin1 are sent with U+FFFD rather than question marks', function (): void {
    $path = tempDirectory().'/legacy.php';
    file_put_contents($path, "<?php\n\$name = 'Caf\xE9';\nthrow new Exception('x');\n");

    $item = utf8ErrorItem(utf8ThrowableAt($path, 3));

    expect($item['context'])->toContain("\$name = 'Caf\u{FFFD}';")
        ->and($item['context'])->not->toContain('?;');
});

test('a console command and its arguments with invalid bytes are repaired, each argument inside its cap', function (): void {
    $item = utf8ErrorItem(new RuntimeException('Broke'), ErrorContext::provided(
        isConsole: true,
        consoleCommand: "import caf\xE9.csv",
        consoleArguments: ["caf\xE9.csv", str_repeat("\xB1", 600)],
    ));

    expect($item['console_command'])->toBe("import caf\u{FFFD}.csv")
        ->and($item['console_arguments'][0])->toBe("caf\u{FFFD}.csv")
        ->and(mb_strlen($item['console_arguments'][1]))->toBe(500)
        ->and(mb_check_encoding($item['console_arguments'][1], 'UTF-8'))->toBeTrue();
});

test('an exception class whose name holds a non-UTF-8 byte is sent with the byte replaced', function (): void {
    // PHP identifiers accept any byte from 0x80 up, so a class declared in a
    // latin1 source file carries that byte in its name.
    $class = "Caf\xE9Exception";

    if (! class_exists($class, false)) {
        eval("final class {$class} extends RuntimeException {}");
    }

    expect(utf8ErrorItem(new $class('Broke'))['type'])->toBe("Caf\u{FFFD}Exception");
});

test('a user id and email with invalid bytes are repaired', function (): void {
    $item = utf8ErrorItem(new RuntimeException('Broke'), overrides: [
        'user_resolver' => static fn (): array => ['id' => "user\xB1", 'email' => "jos\xE9@example.test"],
        'errors' => ['capture_user_email' => true],
    ]);

    expect($item['user'])->toBe(['id' => "user\u{FFFD}", 'email' => "jos\u{FFFD}@example.test"]);
});

test('an exception context that grows past its byte cap once repaired still drops trailing keys to fit', function (): void {
    $throwable = new class('Broke') extends RuntimeException
    {
        /**
         * @return array<string, string>
         */
        public function context(): array
        {
            $context = [];

            for ($index = 0; $index < 8; $index++) {
                $context['key'.$index] = str_repeat("\xB1", 490);
            }

            return $context;
        }
    };

    $context = utf8ErrorItem($throwable)['exception_context'];

    expect($context)->toBeArray()
        ->and(count($context))->toBeLessThan(8)
        ->and(mb_strlen((string) json_encode($context), '8bit'))->toBeLessThanOrEqual(8_192);
});

test('an error item carrying invalid bytes in every field encodes as JSON', function (): void {
    $item = utf8ErrorItem(new RuntimeException("Broke \xB1"), ErrorContext::provided(
        isConsole: false,
        headers: ["x-\xB1" => ["\xB1"], 'referer' => ["https://example.test/\xB1"]],
        url: "https://example.test/\xB1?q=\xB1",
        method: "POST\xB1",
        timestamp: "2026-10-02\xB1",
    ), ['environment' => "prod\xB1", 'framework' => "Frame\xB1"]);

    expect(json_encode($item))->toBeString();
});

test('a log context value and key five levels deep are repaired', function (): void {
    $context = utf8LogItem(context: ['a' => ['b' => ['c' => ['d' => ["key\xB1" => "deep\xB1"]]]]])['context'];

    expect($context)->toBe(['a' => ['b' => ['c' => ['d' => ["key\u{FFFD}" => "deep\u{FFFD}"]]]]]);
});

test('a log context that grows past its byte cap once repaired is replaced by the marker', function (): void {
    // 20,000 latin1 bytes are 60,000 bytes once each becomes a three-byte
    // U+FFFD, so the cap has to be measured after the repair to hold.
    $context = utf8LogItem(context: ['blob' => str_repeat("\xB1", 20_000)])['context'];

    expect($context)->toBe(['_truncated' => 'Context exceeded 50KB limit and was removed']);
});

test('a log message of invalid bytes past its cap is cut inside the cap', function (): void {
    $message = utf8LogItem(str_repeat("\xB1", 60_000))['message'];

    expect(mb_strlen($message))->toBe(50_000)
        ->and(mb_check_encoding($message, 'UTF-8'))->toBeTrue();
});

test('breadcrumb data that grows past its byte cap once repaired is replaced by the marker', function (): void {
    $item = utf8JavaScriptItem([
        'message' => 'Broke',
        'url' => 'https://example.test',
        'breadcrumbs' => [
            ['timestamp' => 't', 'category' => 'c', 'message' => 'm', 'data' => ['blob' => str_repeat("\xB1", 2_000)]],
        ],
    ]);

    expect($item['breadcrumbs'][0]['data'])->toBe(['_truncated' => 'Breadcrumb data exceeded 5KB limit and was removed']);
});

test('the javascript item repairs the strings a form-posted payload and the user agent can carry', function (): void {
    $item = utf8JavaScriptItem([
        'message' => 'Broke',
        'stack' => "at caf\xE9.js:1",
        'type' => "Type\xB1",
        'filename' => "caf\xE9.js",
        'url' => 'https://example.test',
        'timestamp' => "2026\xB1",
        'browser_info' => ['connection_type' => "4g\xB1"],
    ], "Agent\xB1");

    expect($item['stack'])->toBe("at caf\u{FFFD}.js:1")
        ->and($item['type'])->toBe("Type\u{FFFD}")
        ->and($item['filename'])->toBe("caf\u{FFFD}.js")
        ->and($item['timestamp'])->toBe("2026\u{FFFD}")
        ->and($item['user_agent'])->toBe("Agent\u{FFFD}")
        ->and($item['browser_info']['connection_type'])->toBe("4g\u{FFFD}")
        ->and(json_encode($item))->toBeString();
});

test('an event name, url and user id with invalid bytes are repaired', function (): void {
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    $item = (new EventItemBuilder(new SecretScrubber($config, new InternalLogger($config))))->build(
        "order\xB1",
        [],
        ['id' => "user\xB1"],
        '2026-10-02T10:00:00+00:00',
        "https://example.test/caf\xE9",
        'ua-hash',
        'session-hash',
    );

    expect($item['event_name'])->toBe("order\u{FFFD}")
        ->and($item['url'])->toBe("https://example.test/caf\u{FFFD}")
        ->and($item['user'])->toBe(['id' => "user\u{FFFD}"]);
});
