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

function seedSpool(string $directory): void
{
    file_put_contents($directory.'/errors.json', (string) json_encode([
        ['id' => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'data' => ['message' => 'spooled'], 'timestamp' => time()],
    ]));
}

it('drains the buffer from the command line', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    $result = runPhp(['bin/ranetrace-flush'], flushEnvironment($directory));

    expect($result['status'])->toBe(0)
        ->and($result['stderr'])->toBe('')
        ->and(internalLogContents($directory))->toContain('Network error during batch send')
        ->and(json_decode((string) file_get_contents($directory.'/pauses.json'), true)['features']['errors']['reason'])->toBe('network');
});

it('drains only the type it is given', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    $result = runPhp(['bin/ranetrace-flush', '--type=events'], flushEnvironment($directory));

    // Events are empty, so nothing is sent and the spooled error is untouched.
    expect($result['status'])->toBe(0)
        ->and($result['stderr'])->toBe('')
        ->and(internalLogContents($directory))->not->toContain('Network error during batch send')
        ->and(json_decode((string) file_get_contents($directory.'/errors.json'), true))->toHaveCount(1);
});

it('rejects an unknown type', function (): void {
    $result = runPhp(['bin/ranetrace-flush', '--type=page_visits'], flushEnvironment(tempDirectory()));

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toContain('unknown type [page_visits]');
});

it('rejects an unknown argument', function (): void {
    $result = runPhp(['bin/ranetrace-flush', '--wat'], flushEnvironment(tempDirectory()));

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toContain('unknown argument [--wat]');
});

it('prints usage on help', function (): void {
    $result = runPhp(['bin/ranetrace-flush', '--help'], flushEnvironment(tempDirectory()));

    expect($result['status'])->toBe(0)
        ->and($result['stdout'])->toContain('Usage: ranetrace-flush');
});

it('exits 1 and names the directory when the buffer belongs to another user', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);
    $before = (string) file_get_contents($directory.'/errors.json');

    chmod($directory.'/errors.json', 0444);
    chmod($directory, 0550);

    try {
        $result = runPhp(['bin/ranetrace-flush'], flushEnvironment($directory));
        $after = (string) file_get_contents($directory.'/errors.json');
    } finally {
        chmod($directory, 0700);
        chmod($directory.'/errors.json', 0600);
    }

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toStartWith("ranetrace-flush: cannot write to the buffer in [{$directory}]")
        ->and($result['stderr'])->toContain('Run this command as the user your web server runs as.')
        ->and(mb_substr_count($result['stderr'], "\n"))->toBe(1)
        ->and($after)->toBe($before);
})->skip(runsAsRoot(...), 'root ignores file modes');

it('exits 1 when only a lock file belongs to another user', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);
    $before = (string) file_get_contents($directory.'/errors.json');

    touch($directory.'/errors.lock');
    chmod($directory.'/errors.lock', 0444);

    try {
        $result = runPhp(['bin/ranetrace-flush'], flushEnvironment($directory));
    } finally {
        chmod($directory.'/errors.lock', 0600);
    }

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toContain("[{$directory}]")
        ->and($result['stderr'])->toContain('errors.lock')
        ->and((string) file_get_contents($directory.'/errors.json'))->toBe($before);
})->skip(runsAsRoot(...), 'root ignores file modes');

it('drains on shutdown by default', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    $result = runPhp(
        ['-r', 'require "vendor/autoload.php"; Ranetrace\Php\Ranetrace::init([]);'],
        flushEnvironment($directory),
    );

    expect($result['status'])->toBe(0)
        ->and(internalLogContents($directory))->toContain('Network error during batch send');
});

it('leaves the buffer alone on shutdown when the flush is disabled', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    $result = runPhp(
        ['-r', 'require "vendor/autoload.php"; Ranetrace\Php\Ranetrace::init([]);'],
        array_merge(flushEnvironment($directory), ['RANETRACE_FLUSH_ON_SHUTDOWN' => 'false']),
    );

    expect($result['status'])->toBe(0)
        ->and(internalLogContents($directory))->not->toContain('Network error during batch send');
});

function missingKeyLine(): string
{
    return "ranetrace-flush: RANETRACE_KEY is not set in this command's environment, so nothing is sent. "
        .'This command reads the environment only: a key your application loads from a .env file or sets in its bootstrap does not reach it. '
        ."Set it in the cron job's environment.\n";
}

/**
 * The developer's own shell may hold a RANETRACE_KEY, and the subprocess
 * inherits the environment, so a keyless case passes the key as a blank value
 * rather than leaving it out.
 *
 * @param  array<string, string>  $overrides
 * @return array<string, string>
 */
function keylessFlushEnvironment(string $directory, array $overrides = []): array
{
    return array_merge(flushEnvironment($directory), ['RANETRACE_KEY' => ''], $overrides);
}

it('exits 1 with one line and leaves the spool and the pauses alone when items wait and no key is set', function (string $key): void {
    $directory = tempDirectory();
    seedSpool($directory);
    $before = (string) file_get_contents($directory.'/errors.json');

    $result = runPhp(['bin/ranetrace-flush'], keylessFlushEnvironment($directory, ['RANETRACE_KEY' => $key]));

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toBe(missingKeyLine())
        ->and($result['stdout'])->toBe('')
        ->and((string) file_get_contents($directory.'/errors.json'))->toBe($before)
        ->and(is_file($directory.'/pauses.json'))->toBeFalse()
        ->and(internalLogContents($directory))
        ->toContain('Skipping run, no API key is configured')
        ->not->toContain('Network error during batch send');
})->with([
    'an empty key' => [''],
    'a key of whitespace' => ["  \t"],
]);

it('says the key is missing when the master switch is on and nothing waits', function (): void {
    $result = runPhp(['bin/ranetrace-flush'], keylessFlushEnvironment(tempDirectory()));

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toBe(missingKeyLine());
});

it('stays quiet without a key when the site is switched off and nothing waits', function (): void {
    $directory = tempDirectory();

    $result = runPhp(['bin/ranetrace-flush'], keylessFlushEnvironment($directory, ['RANETRACE_ENABLED' => 'false']));

    expect($result['status'])->toBe(0)
        ->and($result['stderr'])->toBe('')
        ->and(internalLogContents($directory))->toBe('');
});

it('says the key is missing when the site is switched off but items wait', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    $result = runPhp(['bin/ranetrace-flush'], keylessFlushEnvironment($directory, ['RANETRACE_ENABLED' => 'false']));

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toBe(missingKeyLine())
        ->and(json_decode((string) file_get_contents($directory.'/errors.json'), true))->toHaveCount(1);
});

it('says the key is missing when items of another type than the one named wait', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    $result = runPhp(
        ['bin/ranetrace-flush', '--type=events'],
        keylessFlushEnvironment($directory, ['RANETRACE_ENABLED' => 'false']),
    );

    expect($result['status'])->toBe(1)
        ->and($result['stderr'])->toBe(missingKeyLine());
});

it('sends at once on a keyed flush after a keyless one', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    runPhp(['bin/ranetrace-flush'], keylessFlushEnvironment($directory));
    $result = runPhp(['bin/ranetrace-flush'], flushEnvironment($directory));

    expect($result['status'])->toBe(0)
        ->and($result['stderr'])->toBe('')
        ->and(internalLogContents($directory))->toContain('Network error during batch send');
});

it('leaves the spool and the pauses alone on a shutdown flush without a key', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);
    $before = (string) file_get_contents($directory.'/errors.json');

    $result = runPhp(
        ['-r', 'require "vendor/autoload.php"; Ranetrace\Php\Ranetrace::init([]);'],
        keylessFlushEnvironment($directory),
    );

    expect($result['status'])->toBe(0)
        ->and($result['stderr'])->toBe('')
        ->and((string) file_get_contents($directory.'/errors.json'))->toBe($before)
        ->and(is_file($directory.'/pauses.json'))->toBeFalse();
});

it('names the missing key before the buffer it cannot use', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    touch($directory.'/errors.lock');
    chmod($directory.'/errors.lock', 0444);

    try {
        $result = runPhp(['bin/ranetrace-flush'], keylessFlushEnvironment($directory));
    } finally {
        chmod($directory.'/errors.lock', 0600);
    }

    $lines = explode("\n", mb_rtrim($result['stderr'], "\n"));

    expect($result['status'])->toBe(1)
        ->and($lines)->toHaveCount(2)
        ->and($lines[0]."\n")->toBe(missingKeyLine())
        ->and($lines[1])->toStartWith("ranetrace-flush: cannot write to the buffer in [{$directory}]");
})->skip(runsAsRoot(...), 'root ignores file modes');

it('sends one heartbeat from the cron flush with an empty buffer, and none on a second run within five minutes', function (): void {
    $directory = tempDirectory();

    $run = againstFakeApi(static fn (array $api): array => [
        runPhp(['bin/ranetrace-flush'], array_merge(flushEnvironment($directory), $api)),
        runPhp(['bin/ranetrace-flush'], array_merge(flushEnvironment($directory), $api)),
    ]);

    expect($run['requests'])->toBe([[
        'path' => '/v1/heartbeat',
        'user_agent' => 'Ranetrace-PHP/Heartbeat/1.0',
        'body' => (string) json_encode(['sdk' => 'php', 'sdk_version' => Composer\InstalledVersions::getPrettyVersion('ranetrace/ranetrace-php')]),
    ]])
        ->and($run['result'][0])->toBe(['status' => 0, 'stdout' => '', 'stderr' => ''])
        ->and($run['result'][1])->toBe(['status' => 0, 'stdout' => '', 'stderr' => ''])
        ->and(is_file($directory.'/pauses.json'))->toBeFalse();
});

it('sends the heartbeat after the drain', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    $run = againstFakeApi(static fn (array $api): array => runPhp(
        ['bin/ranetrace-flush'],
        array_merge(flushEnvironment($directory), $api),
    ));

    expect(array_column($run['requests'], 'path'))->toBe(['/v1/errors/store', '/v1/heartbeat'])
        ->and($run['result']['status'])->toBe(0);
});

it('sends a heartbeat on a run that drains one named type', function (): void {
    $directory = tempDirectory();

    $run = againstFakeApi(static fn (array $api): array => runPhp(
        ['bin/ranetrace-flush', '--type=events'],
        array_merge(flushEnvironment($directory), $api),
    ));

    expect(array_column($run['requests'], 'path'))->toBe(['/v1/heartbeat']);
});

/**
 * The flush at the end of a web request stops whenever a site has no visitors,
 * so a heartbeat from it would have the API call a quiet site stopped.
 */
it('never sends a heartbeat from the shutdown flush', function (bool $spooled, array $expected): void {
    $directory = tempDirectory();

    if ($spooled) {
        seedSpool($directory);
    }

    $run = againstFakeApi(static fn (array $api): array => runPhp(
        ['-r', 'require "vendor/autoload.php"; Ranetrace\Php\Ranetrace::init([]);'],
        array_merge(flushEnvironment($directory), $api),
    ));

    expect(array_column($run['requests'], 'path'))->toBe($expected)
        ->and($run['result']['status'])->toBe(0);
})->with([
    'with an item to drain' => [true, ['/v1/errors/store']],
    'with an empty buffer' => [false, []],
]);

it('sends no heartbeat without a key', function (): void {
    $directory = tempDirectory();

    $run = againstFakeApi(static fn (array $api): array => runPhp(
        ['bin/ranetrace-flush'],
        array_merge(keylessFlushEnvironment($directory), $api),
    ));

    expect($run['requests'])->toBe([])
        ->and($run['result']['status'])->toBe(1)
        ->and($run['result']['stderr'])->toBe(missingKeyLine());
});

it('sends no heartbeat while the master switch is off', function (): void {
    $directory = tempDirectory();

    $run = againstFakeApi(static fn (array $api): array => runPhp(
        ['bin/ranetrace-flush'],
        array_merge(flushEnvironment($directory), $api, ['RANETRACE_ENABLED' => 'false']),
    ));

    expect($run['requests'])->toBe([])
        ->and($run['result'])->toBe(['status' => 0, 'stdout' => '', 'stderr' => '']);
});

it('sends no heartbeat while everything is paused', function (): void {
    $directory = tempDirectory();
    file_put_contents($directory.'/pauses.json', (string) json_encode([
        'global' => ['paused_until' => new DateTimeImmutable('+10 minutes')->format('c'), 'reason' => '401'],
        'features' => [],
    ]));

    $run = againstFakeApi(static fn (array $api): array => runPhp(
        ['bin/ranetrace-flush'],
        array_merge(flushEnvironment($directory), $api),
    ));

    expect($run['requests'])->toBe([])
        ->and($run['result'])->toBe(['status' => 0, 'stdout' => '', 'stderr' => '']);
});

it('keeps the exit code, the spool and the pauses when the heartbeat is answered with a 500', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);
    $before = (string) file_get_contents($directory.'/errors.json');

    // Only events are drained, so the spooled error is still there to compare.
    $run = againstFakeApi(
        static fn (array $api): array => runPhp(
            ['bin/ranetrace-flush', '--type=events'],
            array_merge(flushEnvironment($directory), $api),
        ),
        ['FAKE_API_HEARTBEAT_STATUS' => '500'],
    );

    $log = internalLogContents($directory);

    expect(array_column($run['requests'], 'path'))->toBe(['/v1/heartbeat'])
        ->and($run['result'])->toBe(['status' => 0, 'stdout' => '', 'stderr' => ''])
        ->and((string) file_get_contents($directory.'/errors.json'))->toBe($before)
        ->and(is_file($directory.'/pauses.json'))->toBeFalse()
        ->and(mb_substr_count($log, "\n"))->toBe(1)
        ->and($log)->toContain('Heartbeat was not accepted {"status":500,"message":"Heartbeat refused"}');
});

it('keeps the exit code and sets no pause when the heartbeat cannot reach the api', function (): void {
    $directory = tempDirectory();

    $result = runPhp(['bin/ranetrace-flush'], flushEnvironment($directory));

    $log = internalLogContents($directory);

    expect($result)->toBe(['status' => 0, 'stdout' => '', 'stderr' => ''])
        ->and(is_file($directory.'/pauses.json'))->toBeFalse()
        ->and(mb_substr_count($log, "\n"))->toBe(1)
        ->and($log)->toContain('Heartbeat was not accepted {"status":0,');
});

/**
 * A flush run as another user drains nothing. It is not a worker that runs,
 * so it does not tell the API it is one.
 */
it('sends no heartbeat when it cannot use the buffer', function (): void {
    $directory = tempDirectory();
    seedSpool($directory);

    touch($directory.'/errors.lock');
    chmod($directory.'/errors.lock', 0444);

    try {
        $run = againstFakeApi(static fn (array $api): array => runPhp(
            ['bin/ranetrace-flush'],
            array_merge(flushEnvironment($directory), $api),
        ));
    } finally {
        chmod($directory.'/errors.lock', 0600);
    }

    expect($run['requests'])->toBe([])
        ->and($run['result']['status'])->toBe(1);
})->skip(runsAsRoot(...), 'root ignores file modes');
