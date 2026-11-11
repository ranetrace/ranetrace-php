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
