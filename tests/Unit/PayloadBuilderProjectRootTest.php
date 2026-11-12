<?php

declare(strict_types=1);

use Ranetrace\Php\Contract\WireContract;
use Ranetrace\Php\Errors\ErrorContext;
use Ranetrace\Php\Tests\Contract\DescriptorValidator;

/**
 * The absolute path of the project says how the server is laid out, so it
 * stays on the host: every path under it is sent relative to it. These tests
 * follow the root through the free-form fields of an error item, where it
 * arrives inside a text rather than as a path of its own.
 */

/**
 * What a failing Blade view throws, rebuilt without a framework: an exception
 * thrown from a compiled view under the project root, whose message names the
 * template by its absolute path, wrapping the error that caused it. The
 * compiled view ends in the marker Laravel writes there, which names the
 * template by its absolute path too.
 */
function viewErrorUnder(string $root): RuntimeException
{
    $throw = require writeProjectFile($root, 'storage/framework/views/3f2a.php', <<<PHP
        <?php

        return static function (string \$root): never {
            throw new RuntimeException(
                "Undefined variable \\\$user (View: {\$root}/resources/views/profile.blade.php)",
                0,
                new ErrorException("include({\$root}/resources/views/partials/missing.php): Failed to open stream"),
            );
        };
        ?>
        <?php /**PATH {$root}/resources/views/profile.blade.php ENDPATH**/ ?>
        PHP);

    try {
        $throw($root);
    } catch (RuntimeException $exception) {
        return $exception;
    }
}

test('the message of an error names a file under the project root by its relative path', function (): void {
    $root = frameProject();

    $payload = framePayload(frameBuilder($root), viewErrorUnder($root));

    expect($payload['message'])->toBe('Undefined variable $user (View: resources/views/profile.blade.php)');
});

test('the message of a previous exception loses the project root too', function (): void {
    $root = frameProject();

    $payload = framePayload(frameBuilder($root), viewErrorUnder($root));

    expect($payload['previous'][0]['message'])->toBe('include(resources/views/partials/missing.php): Failed to open stream');
});

test('a source line that names the project root is sent without it, in the context and in a frame', function (): void {
    $root = frameProject();

    $payload = framePayload(frameBuilder($root), viewErrorUnder($root));

    expect($payload['context'])->toContain('<?php /**PATH resources/views/profile.blade.php ENDPATH**/ ?>')
        ->and($payload['context'])->not->toContain($root)
        ->and(json_encode($payload['frames'], JSON_UNESCAPED_SLASHES))->not->toContain($root);
});

test('the text trace names its files relative to the project root', function (): void {
    $root = frameProject();

    $import = require writeProjectFile($root, 'app/Importer.php', <<<'PHP'
        <?php

        return static function (callable $run): void {
            $run(static function (): never {
                throw new RuntimeException('Import failed');
            });
        };
        PHP);
    $run = require writeProjectFile($root, 'vendor/acme/runner/Runner.php', <<<'PHP'
        <?php

        return static function (callable $callback): void {
            $callback();
        };
        PHP);

    try {
        $import($run);
    } catch (RuntimeException $exception) {
        $payload = framePayload(frameBuilder($root), $exception);
    }

    expect($payload['trace'])->toContain('#0 vendor/acme/runner/Runner.php(4): ')
        ->and($payload['trace'])->toContain('{closure:app/Importer.php:3}')
        ->and($payload['trace'])->toContain('#1 app/Importer.php(4): ')
        ->and($payload['trace'])->not->toContain($root);
});

test('a console command started by its absolute path is sent by its relative one', function (): void {
    $root = frameProject();

    $payload = frameBuilder($root)->build(new RuntimeException('boom'), ErrorContext::provided(
        isConsole: true,
        consoleCommand: "{$root}/artisan import:run --file={$root}/storage/import.csv",
        consoleArguments: ["{$root}/artisan", 'import:run', "--file={$root}/storage/import.csv"],
    ));

    expect($payload['console_command'])->toBe('artisan import:run --file=storage/import.csv')
        ->and($payload['console_arguments'])->toBe(['artisan', 'import:run', '--file=storage/import.csv']);
});

test('a path in the exception context loses the project root', function (): void {
    $root = frameProject();

    $exception = new class("{$root}/storage/import.csv") extends RuntimeException
    {
        /**
         * @return array<string, mixed>
         */
        public function context(): array
        {
            return ['file' => $this->getMessage(), 'rows' => 12, 'nested' => ['directory' => dirname($this->getMessage())]];
        }
    };

    expect(framePayload(frameBuilder($root), $exception)['exception_context'])
        ->toBe(['file' => 'storage/import.csv', 'rows' => 12, 'nested' => ['directory' => 'storage']]);
});

test('no field of a view error holds the project root, and the backend still accepts the item', function (): void {
    $root = frameProject();

    $payload = frameBuilder($root)->build(viewErrorUnder($root), ErrorContext::provided(
        isConsole: true,
        consoleCommand: "{$root}/artisan view:render",
        consoleArguments: ["{$root}/artisan", 'view:render'],
    ));

    expect(json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR))->not->toContain($root)
        ->and(DescriptorValidator::violations(WireContract::item('errors')['fields'], $payload, true))->toBe([]);
});

test('the root is taken off the message before it is cut to length, so a cut cannot leave half of it', function (): void {
    $root = frameProject();

    // 17 characters once the root is off, so 700 of them pass the 10,000 cap.
    $payload = framePayload(frameBuilder($root), new RuntimeException(str_repeat("{$root}/storage/file.txt ", 700)));

    expect($payload['message'])->toEndWith('... (truncated)')
        ->and($payload['message'])->toStartWith('storage/file.txt storage/file.txt ')
        ->and($payload['message'])->not->toContain(mb_substr($root, 0, 12));
});

test('a root strip that cannot run costs the strip, never the error report or its secret scrub', function (): void {
    // A root PCRE cannot build a pattern from, on a host that throws on the
    // warning PCRE raises for it.
    $root = frameProject();
    $builder = frameBuilder($root, ['project_root' => str_repeat('/segment', 10_000)]);

    set_error_handler(static function (int $level, string $message): never {
        throw new ErrorException($message, 0, $level);
    });

    try {
        $payload = framePayload($builder, new RuntimeException("Could not open {$root}/storage/import.csv with password=hunter2"));
    } finally {
        restore_error_handler();
    }

    expect($payload['message'])->toBe("Could not open {$root}/storage/import.csv with password=[REDACTED]")
        ->and($payload['type'])->toBe(RuntimeException::class)
        ->and($payload['frames'])->not->toBeEmpty()
        ->and(mb_substr_count(frameDiagnostics($root), 'could not take the project root off'))->toBe(1);
});

/**
 * A zero-downtime deployment: the release lives in `releases/1` and is reached
 * through the symlink `current`, the way a cron entry types it. PHP names the
 * files it loads by their real path, so the project root is the release.
 *
 * @return array{root: string, current: string}
 */
function symlinkedDeployment(): array
{
    $base = frameProject();
    writeProjectFile($base, 'releases/1/artisan', "<?php\n");
    symlink($base.'/releases/1', $base.'/current');

    return ['root' => (string) realpath($base.'/releases/1'), 'current' => $base.'/current'];
}

test('a console command started through a symlinked deployment is sent relative to the release it runs', function (): void {
    ['root' => $root, 'current' => $current] = symlinkedDeployment();

    $payload = frameBuilder($root)->build(new RuntimeException('boom'), ErrorContext::provided(
        isConsole: true,
        consoleCommand: "{$current}/artisan schedule:run",
        consoleArguments: ["{$current}/artisan", 'schedule:run'],
    ));

    expect($payload['console_command'])->toBe('artisan schedule:run')
        ->and($payload['console_arguments'])->toBe(['artisan', 'schedule:run']);
});

test('only the leading script path of the command line is resolved', function (): void {
    ['root' => $root, 'current' => $current] = symlinkedDeployment();

    $payload = frameBuilder($root)->build(new RuntimeException('boom'), ErrorContext::provided(
        isConsole: true,
        consoleCommand: "{$current}/artisan import:run {$current}/artisan",
        consoleArguments: ["{$current}/artisan", 'import:run', "{$current}/artisan"],
    ));

    expect($payload['console_command'])->toBe("artisan import:run {$current}/artisan")
        ->and($payload['console_arguments'])->toBe(['artisan', 'import:run', "{$current}/artisan"]);
});

test('a command line that does not start with the script path keeps it as typed', function (): void {
    ['root' => $root, 'current' => $current] = symlinkedDeployment();

    $payload = frameBuilder($root)->build(new RuntimeException('boom'), ErrorContext::provided(
        isConsole: true,
        consoleCommand: "{$current}/artisanx schedule:run",
        consoleArguments: ["{$current}/artisan", 'schedule:run'],
    ));

    expect($payload['console_command'])->toBe("{$current}/artisanx schedule:run")
        ->and($payload['console_arguments'])->toBe(['artisan', 'schedule:run']);
});

test('a script path that does not exist is sent as typed', function (): void {
    ['root' => $root, 'current' => $current] = symlinkedDeployment();

    $payload = frameBuilder($root)->build(new RuntimeException('boom'), ErrorContext::provided(
        isConsole: true,
        consoleCommand: "{$current}/missing schedule:run",
        consoleArguments: ["{$current}/missing", 'schedule:run'],
    ));

    expect($payload['console_command'])->toBe("{$current}/missing schedule:run")
        ->and($payload['console_arguments'])->toBe(["{$current}/missing", 'schedule:run']);
});

test('a relative script path is sent as typed, since the working directory may have moved since the start', function (): void {
    ['root' => $root, 'current' => $current] = symlinkedDeployment();
    $workingDirectory = (string) getcwd();

    // From here `current/artisan` would resolve into the release.
    chdir(dirname($current));

    try {
        $payload = frameBuilder($root)->build(new RuntimeException('boom'), ErrorContext::provided(
            isConsole: true,
            consoleCommand: 'current/artisan schedule:run',
            consoleArguments: ['current/artisan', 'schedule:run'],
        ));
    } finally {
        chdir($workingDirectory);
    }

    expect($payload['console_command'])->toBe('current/artisan schedule:run')
        ->and($payload['console_arguments'])->toBe(['current/artisan', 'schedule:run']);
});

test('a web context sends no command line, symlinked or not', function (): void {
    ['root' => $root, 'current' => $current] = symlinkedDeployment();

    $payload = frameBuilder($root)->build(new RuntimeException('boom'), ErrorContext::provided(
        isConsole: false,
        consoleCommand: "{$current}/artisan schedule:run",
        consoleArguments: ["{$current}/artisan", 'schedule:run'],
    ));

    expect($payload['console_command'])->toBeNull()
        ->and($payload['console_arguments'])->toBeNull();
});

test('a script path that open_basedir keeps from being resolved costs nothing on a host whose error handler throws', function (): void {
    // open_basedir can only be tightened within a process, so the build runs
    // in one of its own. realpath() warns about a path outside it, and the
    // handler turns that warning into an exception.
    $script = <<<'PHP'
        require 'vendor/autoload.php';

        set_error_handler(static function (int $level, string $message): never {
            throw new ErrorException($message, 0, $level);
        });

        $config = new Ranetrace\Php\Config(['key' => 'test-api-key-12345', 'project_root' => getcwd(), 'internal_logging' => ['enabled' => false]]);
        $log = new Ranetrace\Php\Support\InternalLogger($config);
        $builder = new Ranetrace\Php\Errors\PayloadBuilder($config, new Ranetrace\Php\Support\SecretScrubber($config, $log), $log);

        $payload = $builder->build(new RuntimeException('boom'), Ranetrace\Php\Errors\ErrorContext::provided(
            isConsole: true,
            consoleCommand: PHP_BINARY.' --version',
            consoleArguments: [PHP_BINARY, '--version'],
        ));

        echo json_encode([$payload['console_command'], $payload['console_arguments']]);
        PHP;

    $repository = dirname(__DIR__, 2);
    $process = proc_open(
        [PHP_BINARY, '-d', 'open_basedir='.$repository, '-r', $script],
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        $repository,
    );

    $stdout = (string) stream_get_contents($pipes[1]);
    $stderr = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $status = proc_close($process);

    expect($status)->toBe(0, $stderr)
        ->and(json_decode($stdout, true))->toBe([PHP_BINARY.' --version', [PHP_BINARY, '--version']]);
});

/**
 * PHP names an anonymous class by its parent, a NUL byte, the absolute path of
 * the file that declares it and the line: `RuntimeException@anonymous` + NUL +
 * `/abs/app/Jobs/Import.php:3$0`, where the number after `$` counts the
 * anonymous classes the process compiled before it.
 */
function anonymousExceptionIn(string $root, string $relative): RuntimeException
{
    return require writeProjectFile($root, $relative, <<<'PHP'
        <?php

        return new class('anonymous') extends RuntimeException {};
        PHP);
}

test('an anonymous exception class is typed by its path relative to the project root, without a NUL byte or a compile counter', function (): void {
    $root = frameProject();

    $payload = framePayload(frameBuilder($root), anonymousExceptionIn($root, 'app/Jobs/Import.php'));

    expect($payload['type'])->toBe('RuntimeException@anonymous app/Jobs/Import.php:3');
});

test('an anonymous exception class keeps one type however many anonymous classes were compiled before it', function (): void {
    $root = frameProject();
    $builder = frameBuilder($root);

    // Requiring the file again compiles the class again, under the next counter.
    $first = anonymousExceptionIn($root, 'app/Jobs/Import.php');
    $second = anonymousExceptionIn($root, 'app/Jobs/Import.php');

    expect($first::class)->not->toBe($second::class)
        ->and(framePayload($builder, $first)['type'])->toBe(framePayload($builder, $second)['type']);
});

test('an anonymous exception class declared under a long path is typed within the contract maximum', function (): void {
    $root = frameProject();
    $exception = anonymousExceptionIn($root, str_repeat('deeply-nested-directory/', 12).'Import.php');

    // A root that does not match keeps the whole path, the longest type there is.
    $payload = framePayload(frameBuilder($root, ['project_root' => '/elsewhere']), $exception);

    expect(mb_strlen($exception::class))->toBeGreaterThan(255)
        ->and(mb_strlen($payload['type']))->toBe(255)
        ->and($payload['type'])->toStartWith('RuntimeException@anonymous '.$root.'/deeply-nested-directory/')
        ->and($payload['type'])->toEndWith('... (truncated)')
        ->and(DescriptorValidator::violations(WireContract::item('errors')['fields'], $payload, true))->toBe([]);
});

test('an ordinary exception class is typed exactly as PHP names it', function (): void {
    $root = frameProject();

    expect(framePayload(frameBuilder($root), new InvalidArgumentException('boom'))['type'])->toBe(InvalidArgumentException::class);
});
