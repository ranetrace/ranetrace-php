<?php

declare(strict_types=1);

/**
 * `bin/ranetrace-test` in a real subprocess, because its whole job is to
 * bootstrap itself from the environment. Every run points at an unroutable base
 * URL, so the sends fail at connect time and nothing reaches a real host.
 *
 * The helpers are named for this file: Pest loads every test file into one
 * process, and `RanetraceFlushBinaryTest` has helpers of its own.
 *
 * @param  array<int, string>  $arguments
 * @param  array<string, string>  $environment
 * @return array{status: int, stdout: string, stderr: string}
 */
function runTestBinary(array $arguments, array $environment): array
{
    $process = proc_open(
        array_merge([PHP_BINARY, 'bin/ranetrace-test'], $arguments),
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        dirname(__DIR__, 2),
        array_merge(getenv(), $environment),
    );

    if (! is_resource($process)) {
        return ['status' => 1, 'stdout' => '', 'stderr' => 'could not start subprocess'];
    }

    $stdout = (string) stream_get_contents($pipes[1]);
    $stderr = (string) stream_get_contents($pipes[2]);

    fclose($pipes[1]);
    fclose($pipes[2]);

    return ['status' => proc_close($process), 'stdout' => $stdout, 'stderr' => $stderr];
}

/**
 * @return array<string, string>
 */
function testBinaryEnvironment(string $directory): array
{
    return [
        'RANETRACE_KEY' => 'test-api-key-12345',
        'RANETRACE_BUFFER_PATH' => $directory,
        // Port 1 refuses instantly.
        'RANETRACE_BASE_URL' => 'http://127.0.0.1:1/v1',
        'RANETRACE_INTERNAL_LOGGING_ENABLED' => 'true',
        'RANETRACE_INTERNAL_STDERR_FALLBACK' => 'false',
    ];
}

it('exits 1 and names the base url it could not reach, leaving the spool and the pauses alone', function (): void {
    $directory = tempDirectory();
    $spooled = (string) json_encode([
        ['id' => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'data' => ['message' => 'spooled'], 'timestamp' => time()],
    ]);
    file_put_contents($directory.'/errors.json', $spooled);

    $result = runTestBinary([], testBinaryEnvironment($directory));

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toBe('')
        ->and($result['stdout'])
        ->toStartWith("Ranetrace test\n")
        ->toContain("  Key      test... (RANETRACE_KEY)\n")
        ->toContain('  errors   failed: could not reach http://127.0.0.1:1/v1 (')
        ->toContain('  events   failed: could not reach http://127.0.0.1:1/v1 (')
        ->toContain("  Waiting  1 error\n")
        ->toEndWith("\nNothing was accepted.\n")
        ->and(is_file($directory.'/pauses.json'))->toBeFalse()
        // The shutdown flush is off: the spooled item was neither sent nor moved.
        ->and((string) file_get_contents($directory.'/errors.json'))->toBe($spooled);
});

it('prints usage on help', function (string $flag): void {
    $result = runTestBinary([$flag], testBinaryEnvironment(tempDirectory()));

    expect($result['status'])->toBe(0)
        ->and($result['stdout'])->toBe("Usage: ranetrace-test\n");
})->with(['--help', '-h']);

it('rejects an unknown argument', function (): void {
    $result = runTestBinary(['--json'], testBinaryEnvironment(tempDirectory()));

    expect($result['status'])->toBe(1)
        ->and($result['stdout'])->toBe('')
        ->and($result['stderr'])->toBe("ranetrace-test: unknown argument [--json].\n");
});

it('says the key is missing from its environment and sends nothing', function (): void {
    $directory = tempDirectory();

    $result = runTestBinary([], array_merge(testBinaryEnvironment($directory), ['RANETRACE_KEY' => '']));

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toBe('')
        ->and($result['stdout'])
        ->toContain("  Key      not set\n")
        ->toContain("RANETRACE_KEY is not set in this command's environment, so nothing is captured or sent. This command reads the environment only")
        ->not->toContain('could not reach')
        ->and(glob($directory.'/internal-*.log') ?: [])->toBe([]);
});

/**
 * A binary that is not in `composer.json`, not executable or export-ignored
 * works in this checkout and is missing from every install.
 */
it('ships as an executable composer binary', function (): void {
    $root = dirname(__DIR__, 2);
    $composer = json_decode((string) file_get_contents($root.'/composer.json'), true);
    $exportIgnored = array_filter(
        explode("\n", (string) file_get_contents($root.'/.gitattributes')),
        static fn (string $line): bool => str_contains($line, 'export-ignore'),
    );

    expect($composer['bin'])->toContain('bin/ranetrace-test')
        ->and(is_executable($root.'/bin/ranetrace-test'))->toBeTrue()
        ->and(implode("\n", $exportIgnored))
        ->not->toContain('bin/ranetrace-test')
        ->not->toContain('/resources ')
        ->not->toContain('resources/test-exception.php');
});
