<?php

declare(strict_types=1);

/**
 * `bin/release-check` in a real subprocess, as a release session runs it. The
 * API it asks is either unreachable or `tests/Doubles/fake-api.php` on PHP's
 * built-in server, so nothing reaches a real host.
 *
 * The helpers are named for this file: Pest loads every test file into one
 * process.
 *
 * @param  array<int, string>  $arguments
 * @param  array<string, string>  $environment
 * @return array{status: int, stdout: string, stderr: string}
 */
function runReleaseCheck(array $arguments, array $environment): array
{
    $process = proc_open(
        array_merge([PHP_BINARY, 'bin/release-check'], $arguments),
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        dirname(__DIR__, 2),
        array_merge(getenv(), ['RANETRACE_RELEASE_KEY_FILE' => ''], $environment),
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

function releaseCheckKeyFile(string $contents = "test-api-key-12345\n"): string
{
    $file = tempDirectory().'/release-check-key';
    file_put_contents($file, $contents);

    return $file;
}

/**
 * Run the release check against the fake API, which refuses the item sent to
 * the endpoint path $refuses, or none.
 *
 * @return array{status: int, stdout: string, stderr: string}
 */
function runReleaseCheckAgainstFakeApi(string $refuses = ''): array
{
    $probe = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) mb_substr((string) mb_strrchr((string) stream_socket_get_name($probe, false), ':'), 1);
    fclose($probe);

    $server = proc_open(
        [PHP_BINARY, '-S', "127.0.0.1:{$port}", 'tests/Doubles/fake-api.php'],
        [1 => ['file', '/dev/null', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        dirname(__DIR__, 2),
        array_merge(getenv(), ['FAKE_API_REFUSES' => $refuses]),
    );

    try {
        // The built-in server writes one line to stderr once it listens.
        fgets($pipes[2]);

        return runReleaseCheck([releaseCheckKeyFile()], ['RANETRACE_BASE_URL' => "http://127.0.0.1:{$port}/v1"]);
    } finally {
        if (is_resource($server)) {
            proc_terminate($server);
            proc_close($server);
        }
    }
}

it('exits 0 and names every item type when the api takes them all', function (): void {
    $result = runReleaseCheckAgainstFakeApi();

    expect($result['stderr'])->toBe('')
        ->and($result['stdout'])
        ->toStartWith('Release check against http://127.0.0.1:')
        ->toContain("  errors             accepted\n")
        ->toContain("  events             accepted\n")
        ->toContain("  logs               accepted\n")
        ->toContain("  javascript_errors  accepted\n")
        ->toEndWith("\nThe API took the item of every type.\n")
        ->and($result['status'])->toBe(0);
});

it('exits 1 and says not to tag when the api refuses the item of one type', function (string $path, string $type): void {
    $result = runReleaseCheckAgainstFakeApi($path);

    expect($result['status'])->toBe(1)
        ->and($result['stdout'])
        ->toMatch('/^  '.$type.' +refused: the API did not store the test item/m')
        ->toEndWith("\nThe API did not take every item. Do not tag: find out which side is behind first.\n")
        ->and(mb_substr_count($result['stdout'], ' accepted'))->toBe(3);
})->with([
    'errors' => ['/errors/store', 'errors'],
    'events' => ['/events/store', 'events'],
    'logs' => ['/logs/store', 'logs'],
    'javascript errors' => ['/javascript-errors/store', 'javascript_errors'],
]);

it('exits 1 for every type when the api cannot be reached, and leaves no spool behind', function (): void {
    $before = glob(sys_get_temp_dir().'/ranetrace-release-check-*') ?: [];

    // Port 1 refuses instantly.
    $result = runReleaseCheck([releaseCheckKeyFile()], ['RANETRACE_BASE_URL' => 'http://127.0.0.1:1/v1']);

    expect($result['status'])->toBe(1)
        ->and(mb_substr_count($result['stdout'], 'failed: could not reach http://127.0.0.1:1/v1'))->toBe(4)
        ->and($result['stdout'])->toContain('Do not tag')
        ->and(array_diff(glob(sys_get_temp_dir().'/ranetrace-release-check-*') ?: [], $before))->toBe([]);
});

it('never prints the key', function (): void {
    $result = runReleaseCheck([releaseCheckKeyFile("a-very-secret-ingest-key\n")], ['RANETRACE_BASE_URL' => 'http://127.0.0.1:1/v1']);

    expect($result['stdout'].$result['stderr'])->not->toContain('a-very-secret-ingest-key');
});

it('exits 1 without sending when the key file is missing or empty', function (Closure $keyFile, string $message): void {
    $result = runReleaseCheck([$keyFile()], ['RANETRACE_BASE_URL' => 'http://127.0.0.1:1/v1']);

    expect($result['status'])->toBe(1)
        ->and($result['stdout'])->toBe('')
        ->and($result['stderr'])->toContain($message);
})->with([
    'missing' => [fn (): string => tempDirectory().'/no-such-file', 'no readable key file at ['],
    'empty' => [fn (): string => releaseCheckKeyFile("\n"), 'is empty'],
]);

it('reads the key file named in the environment when no argument names one', function (): void {
    $result = runReleaseCheck([], [
        'RANETRACE_RELEASE_KEY_FILE' => releaseCheckKeyFile(),
        'RANETRACE_BASE_URL' => 'http://127.0.0.1:1/v1',
    ]);

    expect($result['stdout'])->toStartWith("Release check against http://127.0.0.1:1/v1\n");
});
