<?php

declare(strict_types=1);

/**
 * The two drain paths that only exist outside a test process: the cron binary
 * and the shutdown handler. Both are exercised in a real subprocess, because a
 * shutdown function cannot be observed from inside the request that registered
 * it, and the binary's whole job is to bootstrap itself.
 *
 * Every subprocess points at an unroutable base URL, so the send fails at
 * connect time. That failure is the assertion: a network error is logged and the
 * feature is paused, which is only possible if a drain actually ran.
 *
 * @param  array<int, string>  $command
 * @param  array<string, string>  $environment
 * @return array{status: int, stdout: string, stderr: string}
 */
function runFlushSubprocess(array $command, array $environment): array
{
    $process = proc_open(
        array_merge([PHP_BINARY], $command),
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
function flushEnvironment(string $directory): array
{
    return [
        'RANETRACE_KEY' => 'test-api-key-12345',
        'RANETRACE_BUFFER_PATH' => $directory,
        // Port 1 refuses instantly, so a run fails at connect time rather than
        // reaching any real host.
        'RANETRACE_BASE_URL' => 'http://127.0.0.1:1/v1',
        'RANETRACE_INTERNAL_LOGGING_ENABLED' => 'true',
        'RANETRACE_INTERNAL_STDERR_FALLBACK' => 'false',
    ];
}

function subprocessInternalLog(string $directory): string
{
    $files = glob($directory.'/internal-*.log') ?: [];

    return implode('', array_map(static fn (string $file): string => (string) file_get_contents($file), $files));
}

function seedSpool(string $directory): void
{
    file_put_contents($directory.'/errors.json', (string) json_encode([
        ['id' => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'data' => ['message' => 'spooled'], 'timestamp' => time()],
    ]));
}

it('drains the buffer from the command line', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    $result = runFlushSubprocess(['bin/ranetrace-flush'], flushEnvironment($directory));

    expect($result['status'])->toBe(0)
        ->and($result['stderr'])->toBe('')
        ->and(subprocessInternalLog($directory))->toContain('Network error during batch send')
        ->and(json_decode((string) file_get_contents($directory.'/pauses.json'), true)['features']['errors']['reason'])->toBe('network');
});

it('drains only the type it is given', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    $result = runFlushSubprocess(['bin/ranetrace-flush', '--type=events'], flushEnvironment($directory));

    // Events are empty, so nothing is sent and the spooled error is untouched.
    expect($result['status'])->toBe(0)
        ->and(subprocessInternalLog($directory))->not->toContain('Network error during batch send')
        ->and(json_decode((string) file_get_contents($directory.'/errors.json'), true))->toHaveCount(1);
});

it('rejects an unknown type', function (): void {
    $result = runFlushSubprocess(['bin/ranetrace-flush', '--type=page_visits'], flushEnvironment(tempDirectory()));

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toContain('unknown type [page_visits]');
});

it('rejects an unknown argument', function (): void {
    $result = runFlushSubprocess(['bin/ranetrace-flush', '--wat'], flushEnvironment(tempDirectory()));

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toContain('unknown argument [--wat]');
});

it('prints usage on help', function (): void {
    $result = runFlushSubprocess(['bin/ranetrace-flush', '--help'], flushEnvironment(tempDirectory()));

    expect($result['status'])->toBe(0)
        ->and($result['stdout'])->toContain('Usage: ranetrace-flush');
});

it('drains on shutdown by default', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    $result = runFlushSubprocess(
        ['-r', 'require "vendor/autoload.php"; Ranetrace\Php\Ranetrace::init([]);'],
        flushEnvironment($directory),
    );

    expect($result['status'])->toBe(0)
        ->and(subprocessInternalLog($directory))->toContain('Network error during batch send');
});

it('leaves the buffer alone on shutdown when the flush is disabled', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    $result = runFlushSubprocess(
        ['-r', 'require "vendor/autoload.php"; Ranetrace\Php\Ranetrace::init([]);'],
        array_merge(flushEnvironment($directory), ['RANETRACE_FLUSH_ON_SHUTDOWN' => 'false']),
    );

    expect($result['status'])->toBe(0)
        ->and(subprocessInternalLog($directory))->not->toContain('Network error during batch send');
});
