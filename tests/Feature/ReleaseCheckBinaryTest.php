<?php

declare(strict_types=1);

use Ranetrace\Php\Http\Heartbeat;
use Ranetrace\Php\Worker\Worker;

/**
 * `bin/release-check` in a real subprocess, as a release session runs it. The
 * API it asks is either unreachable or `tests/Doubles/fake-api.php` on PHP's
 * built-in server, so nothing reaches a real host.
 *
 * @param  array<int, string>  $arguments
 * @param  array<string, string>  $environment
 * @return array{status: int, stdout: string, stderr: string}
 */
function runReleaseCheck(array $arguments, array $environment): array
{
    return runPhp(['bin/release-check', ...$arguments], ['RANETRACE_RELEASE_KEY_FILE' => '', ...$environment]);
}

function releaseCheckKeyFile(string $contents = "test-api-key-12345\n"): string
{
    $file = tempDirectory().'/release-check-key';
    file_put_contents($file, $contents);

    return $file;
}

/**
 * Run the release check against the fake API, which refuses the item sent to
 * the endpoint path $refuses, or none, and answers the heartbeat with
 * $heartbeatStatus.
 *
 * @return array{status: int, stdout: string, stderr: string}
 */
function runReleaseCheckAgainstFakeApi(string $refuses = '', int $heartbeatStatus = 200): array
{
    return againstFakeApi(
        static fn (array $api): array => runReleaseCheck([releaseCheckKeyFile()], $api),
        ['FAKE_API_REFUSES' => $refuses, 'FAKE_API_HEARTBEAT_STATUS' => (string) $heartbeatStatus],
    )['result'];
}

it('exits 0 and names every item type and the heartbeat when the api takes them all', function (): void {
    $result = runReleaseCheckAgainstFakeApi();

    expect($result['stderr'])->toBe('')
        ->and($result['stdout'])
        ->toStartWith('Release check against http://127.0.0.1:')
        ->toContain("  errors             accepted\n")
        ->toContain("  events             accepted\n")
        ->toContain("  logs               accepted\n")
        ->toContain("  javascript_errors  accepted\n")
        ->toContain("  heartbeat          accepted\n")
        ->toEndWith("\nThe API took the item of every type, and the heartbeat.\n")
        ->and($result['status'])->toBe(0);
});

it('exits 1 and says not to tag when the api refuses the item of one type', function (string $path, string $type): void {
    $result = runReleaseCheckAgainstFakeApi($path);

    expect($result['status'])->toBe(1)
        ->and($result['stdout'])
        ->toMatch('/^  '.$type.' +refused: the API did not store the test item/m')
        ->toEndWith("\nThe API did not take everything this commit sends. Do not tag: find out which side is behind first.\n")
        ->and(mb_substr_count($result['stdout'], ' accepted'))->toBe(4);
})->with([
    'errors' => ['/errors/store', 'errors'],
    'events' => ['/events/store', 'events'],
    'logs' => ['/logs/store', 'logs'],
    'javascript errors' => ['/javascript-errors/store', 'javascript_errors'],
]);

it('exits 1 and says not to tag when the api does not take the heartbeat', function (int $status): void {
    $result = runReleaseCheckAgainstFakeApi(heartbeatStatus: $status);

    expect($result['status'])->toBe(1)
        ->and($result['stdout'])
        ->toContain("  heartbeat          refused: the API answered {$status} (Heartbeat refused)\n")
        ->toEndWith("\nThe API did not take everything this commit sends. Do not tag: find out which side is behind first.\n")
        ->and(mb_substr_count($result['stdout'], ' accepted'))->toBe(4);
})->with([
    'an api without the endpoint' => [404],
    'an api that refuses the body' => [422],
]);

it('sends the heartbeat the cron flush sends', function (): void {
    $requests = againstFakeApi(static fn (array $api): array => runReleaseCheck([releaseCheckKeyFile()], $api))['requests'];

    $heartbeats = array_values(array_filter(
        $requests,
        fn (array $request): bool => $request['path'] === '/v1/heartbeat',
    ));

    expect($heartbeats)->toHaveCount(1)
        ->and($heartbeats[0]['user_agent'])->toBe('Ranetrace-PHP/Heartbeat/1.0')
        ->and(json_decode($heartbeats[0]['body'], true))->toBe(Heartbeat::forPackage(Worker::SDK, Worker::PACKAGE)->body());
});

it('exits 1 for every type and the heartbeat when the api cannot be reached, and leaves no spool behind', function (): void {
    $before = glob(sys_get_temp_dir().'/ranetrace-release-check-*') ?: [];

    // Port 1 refuses instantly.
    $result = runReleaseCheck([releaseCheckKeyFile()], ['RANETRACE_BASE_URL' => 'http://127.0.0.1:1/v1']);

    expect($result['status'])->toBe(1)
        ->and(mb_substr_count($result['stdout'], 'failed: could not reach http://127.0.0.1:1/v1'))->toBe(5)
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
