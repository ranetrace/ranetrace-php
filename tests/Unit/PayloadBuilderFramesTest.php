<?php

declare(strict_types=1);

use Ranetrace\Php\Errors\FrameLocation;
use Ranetrace\Php\Errors\FrameMapper;
use Ranetrace\Php\Errors\PayloadBuilder;

/**
 * The structured frames, their source lines and the previous-exception chain,
 * built from real throwables thrown through real files in a throwaway
 * project: `app/` is the application's own code, `vendor/` a dependency.
 */

/**
 * An application service that hands a closure to a vendor runner, which calls
 * back into the service, which throws. Returns the service and the runner.
 *
 * @return array{0: object, 1: callable}
 */
function nestedCallProject(string $root): array
{
    $service = require writeProjectFile($root, 'app/Service.php', <<<'PHP'
        <?php

        return new class
        {
            public function handle(callable $vendorRunner, object $payload): void
            {
                $vendorRunner(fn () => $this->fail($payload));
            }

            private function fail(object $payload): void
            {
                throw new RuntimeException('Order sync failed');
            }
        };

        PHP);

    $runner = require writeProjectFile($root, 'vendor/acme/runner/Runner.php', <<<'PHP'
        <?php

        return static function (callable $callback): void {
            $callback();
        };

        PHP);

    return [$service, $runner];
}

function nestedCallException(string $root, ?object $payload = null): RuntimeException
{
    [$service, $runner] = nestedCallProject($root);

    try {
        $service->handle($runner, $payload ?? new stdClass);
    } catch (RuntimeException $exception) {
        return $exception;
    }

    throw new LogicException('The service did not throw.');
}

/**
 * Every key at any depth of an array.
 *
 * @param  array<array-key, mixed>  $values
 * @return list<array-key>
 */
function allKeys(array $values): array
{
    $keys = [];

    foreach ($values as $key => $value) {
        $keys[] = $key;

        if (is_array($value)) {
            $keys = [...$keys, ...allKeys($value)];
        }
    }

    return $keys;
}

/**
 * A mapper that answers for one absolute file, the way a compiled-view mapper
 * answers for the compiled views only.
 */
function mapperFor(string $from, string $to, int $line): FrameMapper
{
    return new class($from, $to, $line) implements FrameMapper
    {
        public function __construct(private string $from, private string $to, private int $line) {}

        public function map(FrameLocation $location): ?FrameLocation
        {
            return $location->file === $this->from ? new FrameLocation($this->to, $this->line) : null;
        }
    };
}

test('a nested call becomes structured frames, innermost first, with project-relative paths', function (): void {
    $root = frameProject();
    $payload = framePayload(frameBuilder($root), nestedCallException($root));

    [$fail, $runner, $callback] = $payload['frames'];

    expect($fail)->toMatchArray([
        'index' => 0,
        'file' => 'app/Service.php',
        'line' => 7,
        'function' => 'fail',
        'type' => '->',
        'is_vendor' => false,
    ])
        ->and($runner)->toMatchArray([
            'index' => 1,
            'file' => 'vendor/acme/runner/Runner.php',
            'line' => 4,
            'is_vendor' => true,
            'source' => null,
        ])
        ->and($callback)->toMatchArray([
            'index' => 2,
            'file' => 'app/Service.php',
            'line' => 7,
            'class' => null,
            'function' => '{closure:vendor/acme/runner/Runner.php:3}',
            'type' => null,
            'is_vendor' => false,
        ])
        ->and(array_keys($fail))->toBe(['index', 'file', 'line', 'class', 'function', 'type', 'is_vendor', 'source'])
        ->and($payload['frames_omitted'])->toBe(0)
        ->and($payload['previous'])->toBeNull();
});

test('an app frame carries the lines around its line and a vendor frame carries none', function (): void {
    $root = frameProject();
    $payload = framePayload(frameBuilder($root), nestedCallException($root));

    expect($payload['frames'][0]['source'])->toBe([
        'start_line' => 2,
        'lines' => [
            '',
            'return new class',
            '{',
            '    public function handle(callable $vendorRunner, object $payload): void',
            '    {',
            '        $vendorRunner(fn () => $this->fail($payload));',
            '    }',
            '',
            '    private function fail(object $payload): void',
            '    {',
            "        throw new RuntimeException('Order sync failed');",
        ],
    ])
        ->and($payload['frames'][1]['source'])->toBeNull();
});

/**
 * With `zend.exception_ignore_args` off a frame holds the live arguments, and
 * an argument can be an object holding a credential. Not one byte of them
 * may reach the payload, not even the `args` key.
 */
test('no argument value or args key reaches the payload, even when an argument holds a secret', function (): void {
    $previous = ini_set('zend.exception_ignore_args', '0');

    try {
        $root = frameProject();
        $secret = implode('', ['sk', '_live_', 'q8Zr1Lw0']);
        $exception = nestedCallException($root, new ArrayObject(['credential' => $secret]));

        expect($exception->getTrace()[0])->toHaveKey('args');

        $payload = framePayload(frameBuilder($root), $exception);
        $json = (string) json_encode($payload);

        expect(allKeys($payload['frames']))->not->toContain('args')
            ->and($json)->not->toContain('"args"')
            ->and($json)->not->toContain($secret);
    } finally {
        ini_set('zend.exception_ignore_args', (string) $previous);
    }
});

test('a vendor frame is recognised with forward and back slashes on either side', function (string $root, string $file, bool $isVendor): void {
    $exception = new RuntimeException('boom');
    $mapper = new class($file) implements FrameMapper
    {
        public function __construct(private string $file) {}

        public function map(FrameLocation $location): ?FrameLocation
        {
            return new FrameLocation($this->file, 12);
        }
    };

    $frame = framePayload(frameBuilder($root, [], [$mapper]), $exception)['frames'][0];

    expect($frame['is_vendor'])->toBe($isVendor)
        ->and($frame['source'])->toBeNull();
})->with([
    'posix vendor' => ['/srv/app', '/srv/app/vendor/acme/Lib.php', true],
    'posix app' => ['/srv/app', '/srv/app/app/Lib.php', false],
    'posix lookalike' => ['/srv/app', '/srv/app/vendors/acme/Lib.php', false],
    'windows vendor' => ['C:\\proj', 'C:\\proj\\vendor\\acme\\Lib.php', true],
    'windows app' => ['C:\\proj', 'C:\\proj\\src\\Lib.php', false],
    'mixed separators' => ['C:/proj/', 'C:\\proj\\vendor\\acme\\Lib.php', true],
]);

test('a frame without a file is not vendor and carries no source', function (): void {
    $root = frameProject();

    try {
        array_map(static function (): void {
            throw new RuntimeException('inside a callback');
        }, [1]);
    } catch (RuntimeException $exception) {
    }

    $frame = framePayload(frameBuilder($root), $exception)['frames'][0];

    expect($frame)->toMatchArray([
        'file' => null,
        'line' => null,
        'is_vendor' => false,
        'source' => null,
    ]);
});

test('a previous exception thrown in vendor code still carries its throw site lines', function (): void {
    $root = frameProject();
    $thrower = require writeProjectFile($root, 'vendor/acme/client/Client.php', <<<'PHP'
        <?php

        return static function (): void {
            throw new LogicException('Connection refused');
        };

        PHP);

    $call = require writeProjectFile($root, 'app/Sync.php', <<<'PHP'
        <?php

        return static function (callable $thrower): void {
            try {
                $thrower();
            } catch (LogicException $failure) {
                throw new RuntimeException('Sync failed', 0, $failure);
            }
        };

        PHP);

    try {
        $call($thrower);
    } catch (RuntimeException $exception) {
    }

    $previous = framePayload(frameBuilder($root), $exception)['previous'];

    expect($previous)->toHaveCount(1)
        ->and($previous[0])->toMatchArray([
            'type' => 'LogicException',
            'message' => 'Connection refused',
            'file' => 'vendor/acme/client/Client.php',
            'line' => 4,
            'frames_omitted' => 0,
        ])
        ->and($previous[0]['source']['start_line'])->toBe(1)
        ->and($previous[0]['source']['lines'][3])->toBe("    throw new LogicException('Connection refused');")
        ->and($previous[0]['frames'][0])->toMatchArray(['file' => 'app/Sync.php', 'line' => 5, 'is_vendor' => false])
        ->and($previous[0]['frames'][0]['source'])->not->toBeNull()
        ->and(array_keys($previous[0]))->toBe(['type', 'message', 'file', 'line', 'source', 'frames', 'frames_omitted']);
});

test('switching source capture off sends no source line anywhere', function (array $overrides, ?string $env): void {
    if ($env !== null) {
        withEnv('RANETRACE_ERRORS_CAPTURE_SOURCE', $env);
    }

    $root = frameProject();
    $exception = new RuntimeException('outer', 0, nestedCallException($root));
    $payload = framePayload(frameBuilder($root, $overrides), $exception);

    $sources = array_merge(
        array_column($payload['frames'], 'source'),
        array_column($payload['previous'][0]['frames'], 'source'),
        [$payload['previous'][0]['source']],
    );

    expect($payload['context'])->toBeNull()
        ->and($payload['highlight_line'])->toBeNull()
        ->and(array_filter($sources, static fn (mixed $source): bool => $source !== null))->toBe([])
        ->and($payload['previous'][0]['frames'])->not->toBeEmpty();
})->with([
    'config array' => [['errors' => ['capture_source' => false]], null],
    'environment' => [[], 'false'],
]);

test('source capture is on by default', function (): void {
    $root = frameProject();
    $payload = framePayload(frameBuilder($root), nestedCallException($root));

    expect($payload['context'])->toBeString()
        ->and($payload['highlight_line'])->toBe(6)
        ->and($payload['frames'][0]['source'])->not->toBeNull();
});

test('a long trace keeps its 40 innermost and 10 outermost frames and counts the middle it dropped', function (): void {
    $exception = deepRecursionException(frameProject(), 200);
    $total = count($exception->getTrace());

    $payload = framePayload(frameBuilder(frameProject()), $exception);
    $indexes = array_column($payload['frames'], 'index');

    expect($payload['frames'])->toHaveCount(50)
        ->and($payload['frames_omitted'])->toBe($total - 50)
        ->and($indexes)->toBe([...range(0, 39), ...range($total - 10, $total - 1)]);
});

test('a trace of exactly fifty frames is sent whole', function (): void {
    $probe = deepRecursionException(frameProject(), 1);
    $depth = 51 - count($probe->getTrace());

    $exception = deepRecursionException(frameProject(), $depth);
    $payload = framePayload(frameBuilder(frameProject()), $exception);

    expect(count($exception->getTrace()))->toBe(50)
        ->and(array_column($payload['frames'], 'index'))->toBe(range(0, 49))
        ->and($payload['frames_omitted'])->toBe(0);
});

test('the previous chain is nearest first and stops at five', function (): void {
    $exception = new RuntimeException('level 0');

    for ($level = 1; $level <= 7; $level++) {
        $exception = new RuntimeException('level '.$level, 0, $exception);
    }

    $previous = framePayload(frameBuilder(frameProject()), $exception)['previous'];

    expect(array_column($previous, 'message'))->toBe(['level 6', 'level 5', 'level 4', 'level 3', 'level 2']);
});

test('a previous chain that loops back on itself stops at the first exception already seen', function (): void {
    $outer = new RuntimeException('outer');
    $inner = new LogicException('inner');
    $previousProperty = new ReflectionProperty(Exception::class, 'previous');
    $previousProperty->setValue($outer, $inner);
    $previousProperty->setValue($inner, $outer);

    $selfLoop = new RuntimeException('self');
    $previousProperty->setValue($selfLoop, $selfLoop);

    $builder = frameBuilder(frameProject());

    expect(array_column(framePayload($builder, $outer)['previous'], 'message'))->toBe(['inner'])
        ->and(framePayload($builder, $selfLoop)['previous'])->toBeNull();
});

test('a previous exception message is scrubbed and capped like the item message', function (): void {
    $exception = new RuntimeException('outer', 0, new RuntimeException('login failed password=hunter2 '.str_repeat('x', 12_000)));

    $message = framePayload(frameBuilder(frameProject()), $exception)['previous'][0]['message'];

    expect($message)->toStartWith('login failed password=[REDACTED] ')
        ->and(mb_strlen($message))->toBe(10_000)
        ->and($message)->toEndWith(PayloadBuilder::TRUNCATION_SUFFIX);
});

test('a secret on a source line is scrubbed in the frame source and in the context', function (): void {
    $root = frameProject();
    $configure = require writeProjectFile($root, 'app/Configure.php', <<<'PHP'
        <?php

        return static function (): void {
            $options = ['api_key' => 'sk_live_9f8e7d6c'];

            throw new RuntimeException('misconfigured');
        };

        PHP);

    $call = require writeProjectFile($root, 'app/Boot.php', <<<'PHP'
        <?php

        return static function (callable $configure): void {
            $token = 'secret_token=abc123def';
            $configure();
        };

        PHP);

    try {
        $call($configure);
    } catch (RuntimeException $exception) {
    }

    $payload = framePayload(frameBuilder($root), $exception);
    $json = (string) json_encode($payload);

    expect($payload['frames'][0]['source']['lines'])->toContain("    \$token = '[REDACTED]';")
        ->and($payload['context'])->toContain("'api_key' => '[REDACTED]'")
        ->and($json)->not->toContain('sk_live_9f8e7d6c')
        ->and($json)->not->toContain('abc123def');
});

test('closure and anonymous class names lose the absolute project path and the NUL byte', function (): void {
    $root = frameProject();
    $payload = framePayload(frameBuilder($root), nestedCallException($root));
    $json = (string) json_encode($payload['frames']);

    expect($payload['frames'][0]['class'])->toMatch('/^class@anonymous app\/Service\.php:3\$[0-9a-f]+$/')
        ->and($payload['frames'][1]['function'])->toMatch('/^\{closure:class@anonymous app\/Service\.php:3\$[0-9a-f]+::handle\(\):7\}$/')
        ->and($payload['frames'][2]['function'])->toBe('{closure:vendor/acme/runner/Runner.php:3}')
        ->and($json)->not->toContain($root)
        ->and($json)->not->toContain('\u0000');
});

test('a mapped frame arrives as the template, its line and its source', function (): void {
    $root = frameProject();
    $template = writeProjectFile($root, 'resources/views/orders.blade.php', implode("\n", [
        '<ul>',
        '    @foreach ($orders as $order)',
        '        <li>{{ $order->total() }}</li>',
        '    @endforeach',
        '</ul>',
        '',
    ]));
    $mapper = mapperFor($root.'/app/Service.php', $template, 3);

    $payload = framePayload(frameBuilder($root, [], [$mapper]), nestedCallException($root));

    expect($payload['frames'][0])->toMatchArray([
        'file' => 'resources/views/orders.blade.php',
        'line' => 3,
        'is_vendor' => false,
        'source' => [
            'start_line' => 1,
            'lines' => ['<ul>', '    @foreach ($orders as $order)', '        <li>{{ $order->total() }}</li>', '    @endforeach', '</ul>'],
        ],
    ])
        ->and($payload['frames'][1]['file'])->toBe('vendor/acme/runner/Runner.php');
});

test('a vendor frame mapped into the application gets the application source', function (): void {
    $root = frameProject();
    $template = writeProjectFile($root, 'resources/views/cart.blade.php', "<p>{{ \$cart->total }}</p>\n");
    $mapper = mapperFor($root.'/vendor/acme/runner/Runner.php', $template, 1);

    $frame = framePayload(frameBuilder($root, [], [$mapper]), nestedCallException($root))['frames'][1];

    expect($frame)->toMatchArray([
        'file' => 'resources/views/cart.blade.php',
        'line' => 1,
        'is_vendor' => false,
        'source' => ['start_line' => 1, 'lines' => ['<p>{{ $cart->total }}</p>']],
    ]);
});

test('the mapper maps a previous exception throw site but not the item own throw site', function (): void {
    $root = frameProject();
    $template = writeProjectFile($root, 'resources/views/sync.blade.php', "line one\nline two\n");
    $inner = nestedCallException($root);
    $outer = new RuntimeException('wrapped', 0, $inner);
    (new ReflectionProperty(Exception::class, 'file'))->setValue($outer, $root.'/app/Service.php');
    (new ReflectionProperty(Exception::class, 'line'))->setValue($outer, 12);

    $payload = framePayload(frameBuilder($root, [], [mapperFor($root.'/app/Service.php', $template, 2)]), $outer);

    expect($payload['file'])->toBe('app/Service.php')
        ->and($payload['line'])->toBe(12)
        ->and($payload['context'])->toContain("throw new RuntimeException('Order sync failed');")
        ->and($payload['previous'][0])->toMatchArray([
            'file' => 'resources/views/sync.blade.php',
            'line' => 2,
            'source' => ['start_line' => 1, 'lines' => ['line one', 'line two']],
        ]);
});

test('a mapper that throws costs that one mapping and is logged once, never the report', function (): void {
    $root = frameProject();
    $template = writeProjectFile($root, 'resources/views/orders.blade.php', "<ul></ul>\n");
    $throwing = new class implements FrameMapper
    {
        public function map(FrameLocation $location): ?FrameLocation
        {
            throw new RuntimeException('view finder is not booted');
        }
    };

    $payload = framePayload(frameBuilder($root, [], [$throwing, mapperFor($root.'/app/Service.php', $template, 1)]), nestedCallException($root));

    expect($payload['frames'][0]['file'])->toBe('resources/views/orders.blade.php')
        ->and($payload['frames'][1]['file'])->toBe('vendor/acme/runner/Runner.php')
        ->and(mb_substr_count(frameDiagnostics($root), 'Ranetrace frame mapper failed'))->toBe(1);
});

test('a frame mapper that is not a FrameMapper is a wiring error', function (): void {
    $config = testConfig();

    new PayloadBuilder($config, new Ranetrace\Php\Support\SecretScrubber($config, new Ranetrace\Php\Support\InternalLogger($config)), new Ranetrace\Php\Support\InternalLogger($config), [static fn (): null => null]);
})->throws(InvalidArgumentException::class, 'Every frame mapper must implement');
