<?php

declare(strict_types=1);

use Ranetrace\Php\Contract\WireContract;
use Ranetrace\Php\Support\Scrubber;
use Ranetrace\Php\Support\SecretScrubber;
use Ranetrace\Php\Tests\Contract\DescriptorValidator;

/**
 * The ways structured frames could fail in production that the behaviour
 * tests next door would not catch. Each build runs under an error handler that
 * turns every warning into an exception, the way Laravel's does, so a file
 * check that warns would fail the test instead of passing quietly.
 */

/**
 * @return array<string, mixed>
 */
function hardenedPayload(string $root, Throwable $throwable, ?Scrubber $scrubber = null): array
{
    set_error_handler(static function (int $level, string $message): never {
        throw new ErrorException($message, 0, $level);
    });

    try {
        return framePayload(frameBuilder($root, [], [], $scrubber), $throwable);
    } finally {
        restore_error_handler();
    }
}

/**
 * Every rule of the errors fixture the payload breaks, so a hardening case
 * proves the backend would still accept what came out of it.
 *
 * @param  array<string, mixed>  $payload
 * @return list<string>
 */
function contractViolations(array $payload): array
{
    return DescriptorValidator::violations(WireContract::item('errors')['fields'], $payload, true);
}

/**
 * A scrubber that throws on every string $explodes picks, and on every source
 * window holding a line it picks, and scrubs the rest for real.
 *
 * @param  Closure(string): bool  $explodes
 */
function throwingScrubber(Closure $explodes): Scrubber
{
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    return new class(new SecretScrubber($config, new Ranetrace\Php\Support\InternalLogger($config)), $explodes) implements Scrubber
    {
        public function __construct(private SecretScrubber $real, private Closure $explodes) {}

        public function scrubString(string $value): string
        {
            if (($this->explodes)($value)) {
                throw new RuntimeException('scrubber exploded');
            }

            return $this->real->scrubString($value);
        }

        public function scrubSource(array $lines): array
        {
            foreach ($lines as $line) {
                if (($this->explodes)($line)) {
                    throw new RuntimeException('scrubber exploded');
                }
            }

            return $this->real->scrubSource($lines);
        }

        public function scrubUrl(?string $url): ?string
        {
            return $this->real->scrubUrl($url);
        }

        public function scrubUrlPath(?string $url, array|callable|null $sensitiveValues = null): ?string
        {
            return $this->real->scrubUrlPath($url, $sensitiveValues);
        }

        public function scrubDeep(mixed $data, array|callable|null $sensitiveValues = null): mixed
        {
            return $this->real->scrubDeep($data, $sensitiveValues);
        }
    };
}

/**
 * Throws from a project file whose call line is $callLine, surrounded by
 * whatever $before and $after hold, and returns what was thrown.
 */
function throwThrough(string $root, string $relative, string $before, string $after = ''): RuntimeException
{
    $file = writeProjectFile($root, $relative, "<?php\n".$before."return static function (callable \$next): void { \$next(); };\n".$after);
    $call = require $file;

    try {
        $call(static function (): void {
            throw new RuntimeException('boom');
        });
    } catch (RuntimeException $exception) {
        return $exception;
    }

    throw new LogicException('The call did not throw.');
}

test('an unreadable source file costs that frame its source and nothing else', function (): void {
    if (function_exists('posix_getuid') && posix_getuid() === 0) {
        $this->markTestSkipped('root reads any file');
    }

    $root = frameProject();
    $exception = throwThrough($root, 'app/Locked.php', "\n");
    chmod($root.'/app/Locked.php', 0o000);

    try {
        $payload = hardenedPayload($root, $exception);
    } finally {
        chmod($root.'/app/Locked.php', 0o644);
    }

    $frame = array_values(array_filter($payload['frames'], static fn (array $frame): bool => $frame['file'] === 'app/Locked.php'))[0];

    expect($frame['source'])->toBeNull()
        ->and($frame['line'])->toBe(3)
        ->and($payload['message'])->toBe('boom')
        ->and(contractViolations($payload))->toBe([]);
});

test('code run through eval has no file to read and gets no source', function (): void {
    $root = frameProject();

    try {
        eval('(static function (): void { throw new RuntimeException("evaluated"); })();');
    } catch (RuntimeException $exception) {
    }

    $payload = hardenedPayload($root, $exception);

    expect($exception->getFile())->toContain("eval()'d code")
        ->and($payload['context'])->toBeNull()
        ->and($payload['frames'][0]['file'])->toContain("eval()'d code")
        ->and($payload['frames'][0]['source'])->toBeNull()
        ->and(contractViolations($payload))->toBe([]);
});

test('a ten thousand frame recursion is built in bounded time and memory', function (): void {
    $root = frameProject();
    $exception = deepRecursionException($root, 10_000);
    $total = count($exception->getTrace());

    $memoryBefore = memory_get_usage();
    $started = hrtime(true);
    $payload = hardenedPayload($root, $exception);
    $elapsedMilliseconds = (hrtime(true) - $started) / 1_000_000;
    $memoryUsed = memory_get_usage() - $memoryBefore;

    expect($payload['frames'])->toHaveCount(50)
        ->and($payload['frames_omitted'])->toBe($total - 50)
        ->and($elapsedMilliseconds)->toBeLessThan(1_000)
        ->and($memoryUsed)->toBeLessThan(5 * 1024 * 1024)
        ->and(contractViolations($payload))->toBe([]);
});

test('a minified line is capped and a file of one megabyte or more is not read at all', function (): void {
    $root = frameProject();
    $minified = throwThrough($root, 'app/minified.php', '$bundle = "'.str_repeat('x', 200_000)."\";\n");
    $huge = throwThrough($root, 'app/huge.php', '/*'.str_repeat("filler line\n", 90_000)."*/\n");

    $minifiedFrame = array_values(array_filter(hardenedPayload($root, $minified)['frames'], static fn (array $frame): bool => $frame['file'] === 'app/minified.php'))[0];
    $hugePayload = hardenedPayload($root, $huge);
    $hugeFrame = array_values(array_filter($hugePayload['frames'], static fn (array $frame): bool => $frame['file'] === 'app/huge.php'))[0];

    expect(filesize($root.'/app/huge.php'))->toBeGreaterThanOrEqual(1_048_576)
        ->and(max(array_map(mb_strlen(...), $minifiedFrame['source']['lines'])))->toBe(2_015)
        ->and($hugeFrame['source'])->toBeNull()
        ->and(contractViolations($hugePayload))->toBe([]);
});

test('a binary file in the trace yields encodable lines the contract accepts', function (): void {
    $root = frameProject();
    $exception = throwThrough($root, 'app/binary.php', "/*\x00\x01\xFF\xFE\x89PNG\r\n\x1A\n\x00\x00*/\n", "/*\xC3\x28\x00\xA0\xA1*/\n");

    $payload = hardenedPayload($root, $exception);
    $frame = array_values(array_filter($payload['frames'], static fn (array $frame): bool => $frame['file'] === 'app/binary.php'))[0];

    expect(json_encode($payload))->not->toBeFalse()
        ->and($frame['source'])->not->toBeNull()
        ->and(implode("\n", $frame['source']['lines']))->toContain("\u{FFFD}")
        ->and(contractViolations($payload))->toBe([]);
});

test('invalid UTF-8 on a source line becomes the replacement character in the frame and the context', function (): void {
    $root = frameProject();
    $thrower = require writeProjectFile($root, 'app/Latin1.php', "<?php\n\nreturn static function (): void {\n    \$label = 'caf\xE9';\n    throw new RuntimeException('boom');\n};\n");

    try {
        $thrower();
    } catch (RuntimeException $exception) {
    }

    $wrapped = new RuntimeException('wrapped', 0, $exception);
    $payload = hardenedPayload($root, $exception);
    $previous = hardenedPayload($root, $wrapped)['previous'][0];

    expect($payload['context'])->toContain("\$label = 'caf\u{FFFD}';")
        ->and($previous['source']['lines'])->toContain("    \$label = 'caf\u{FFFD}';")
        ->and(json_encode($payload))->not->toBeFalse();
});

/**
 * `getPrevious()` is final on both `Exception` and `Error`, so no throwable a
 * host can build makes it throw. The guard around the chain covers everything
 * the walk calls, so it is driven here by the next most likely failure inside
 * it: a scrubber that throws on a previous exception's message.
 */
test('a failure while the previous chain is read costs the chain, never the report', function (): void {
    $root = frameProject();

    // Built at run time, so no source line of this file carries the marker
    // and only the previous exception's message trips the scrubber.
    $marker = strrev('niahc denosiop');
    $exception = new RuntimeException('outer', 0, new LogicException($marker));
    $payload = hardenedPayload($root, $exception, throwingScrubber(static fn (string $value): bool => str_contains($value, $marker)));

    expect($payload['message'])->toBe('outer')
        ->and($payload['previous'])->toBeNull()
        ->and($payload['frames'])->not->toBeEmpty()
        ->and(frameDiagnostics($root))->toContain('Ranetrace could not read the previous exception chain')
        ->and(contractViolations($payload))->toBe([]);
});

test('a scrubber that throws on source lines costs those sources, never the report', function (): void {
    $root = frameProject();
    $exception = throwThrough($root, 'app/Service.php', "\n");

    $payload = hardenedPayload($root, $exception, throwingScrubber(static fn (string $value): bool => $value !== $exception->getMessage() && ! str_starts_with($value, '#')));

    expect($payload['message'])->toBe('boom')
        ->and($payload['context'])->toBeNull()
        ->and($payload['highlight_line'])->toBeNull()
        ->and(array_filter(array_column($payload['frames'], 'source')))->toBe([])
        ->and(frameDiagnostics($root))->toContain('Ranetrace could not cut a source window')
        ->and(contractViolations($payload))->toBe([]);
});

test('a scrubber that returns the wrong number of source lines costs those sources, never the report', function (): void {
    // A line out of step with its neighbours would put a scrubbed line beside
    // the wrong line number, or an unscrubbed one in the window.
    $root = frameProject();
    $exception = throwThrough($root, 'app/Short.php', "\n");
    $config = testConfig(['internal_logging' => ['enabled' => false]]);
    $real = new SecretScrubber($config, new Ranetrace\Php\Support\InternalLogger($config));

    $scrubber = new class($real) implements Scrubber
    {
        public function __construct(private SecretScrubber $real) {}

        public function scrubString(string $value): string
        {
            return $this->real->scrubString($value);
        }

        public function scrubSource(array $lines): array
        {
            return array_slice($this->real->scrubSource($lines), 1);
        }

        public function scrubUrl(?string $url): ?string
        {
            return $this->real->scrubUrl($url);
        }

        public function scrubUrlPath(?string $url, array|callable|null $sensitiveValues = null): ?string
        {
            return $this->real->scrubUrlPath($url, $sensitiveValues);
        }

        public function scrubDeep(mixed $data, array|callable|null $sensitiveValues = null): mixed
        {
            return $this->real->scrubDeep($data, $sensitiveValues);
        }
    };

    $payload = hardenedPayload($root, $exception, $scrubber);

    expect($payload['message'])->toBe('boom')
        ->and($payload['context'])->toBeNull()
        ->and(array_filter(array_column($payload['frames'], 'source')))->toBe([])
        ->and(frameDiagnostics($root))->toContain('lines for a window of')
        ->and(contractViolations($payload))->toBe([]);
});

test('a frame whose file is a directory or a stream wrapper path is not read', function (): void {
    $root = frameProject();
    mkdir($root.'/app/Directory.php', 0o775, true);

    $mapper = new class($root) implements Ranetrace\Php\Errors\FrameMapper
    {
        private int $calls = 0;

        public function __construct(private string $root) {}

        public function map(Ranetrace\Php\Errors\FrameLocation $location): ?Ranetrace\Php\Errors\FrameLocation
        {
            return new Ranetrace\Php\Errors\FrameLocation(
                $this->calls++ === 0 ? $this->root.'/app/Directory.php' : 'data://text/plain,'.str_repeat('a', 10),
                1,
            );
        }
    };

    set_error_handler(static function (int $level, string $message): never {
        throw new ErrorException($message, 0, $level);
    });

    try {
        $payload = framePayload(frameBuilder($root, [], [$mapper]), new RuntimeException('boom'));
    } finally {
        restore_error_handler();
    }

    expect($payload['frames'][0]['source'])->toBeNull()
        ->and($payload['frames'][1]['source'])->toBeNull();
});
