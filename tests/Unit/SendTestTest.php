<?php

declare(strict_types=1);

use Ranetrace\Php\Contract\WireContract;
use Ranetrace\Php\Http\RawResponse;
use Ranetrace\Php\Ranetrace;
use Ranetrace\Php\Support\FileLock;
use Ranetrace\Php\Tests\Contract\DescriptorValidator;
use Ranetrace\Php\Tests\Doubles\FakeHttpClient;
use Ranetrace\Php\Worker\TestReport;
use Ranetrace\Php\Worker\TestResult;

/**
 * An SDK on a temp spool and a fake transport, with the shutdown flush off so
 * no drain outlives the temp directory.
 *
 * @param  array<string, mixed>  $overrides
 */
function sendTestSdk(string $directory, FakeHttpClient $http, array $overrides = []): Ranetrace
{
    return new Ranetrace(array_replace_recursive([
        'key' => 'test-api-key-12345',
        'buffer_path' => $directory,
        'environment' => 'testing',
        'flush_on_shutdown' => false,
        'internal_logging' => ['enabled' => false],
    ], $overrides))->withHttpClient($http);
}

/**
 * @param  array<string, mixed>|string  $body
 * @param  array<string, string>  $headers
 */
function sendTestResponse(int $status, array|string $body = ['success' => true, 'items' => ['received' => 1, 'processed' => 1]], array $headers = []): RawResponse
{
    return new RawResponse($status, is_string($body) ? $body : (string) json_encode($body), $headers);
}

/**
 * Every file in a directory with its contents, so a test can tell that nothing
 * was added, removed or changed.
 *
 * @return array<string, string>
 */
function sendTestSnapshot(string $directory): array
{
    $files = [];

    foreach (glob($directory.'/*') ?: [] as $file) {
        $files[basename($file)] = (string) file_get_contents($file);
    }

    return $files;
}

/**
 * An item as the API's validator sees it. The backend runs Laravel's
 * `ConvertEmptyStringsToNull` over the request first, so the empty
 * `user_agent_hash` of an event tracked from the command line reaches its
 * `nullable|string|size:64` rule as null; the descriptor validator does not
 * model that step.
 *
 * @param  array<string, mixed>  $item
 * @return array<string, mixed>
 */
function sendTestAsReceived(array $item): array
{
    return array_map(static fn (mixed $value): mixed => $value === '' ? null : $value, $item);
}

it('sends one error and one event straight to the api, the way a drain sends them', function (): void {
    $http = new FakeHttpClient(sendTestResponse(200), sendTestResponse(200));

    $report = sendTestSdk(tempDirectory(), $http)->sendTest();

    $headers = static fn (string $agent): array => [
        'Authorization' => 'Bearer test-api-key-12345',
        'User-Agent' => $agent,
        'Content-Type' => 'application/json',
        'Accept' => 'application/json',
        'Ranetrace-API-Version' => '1.0',
    ];

    expect($report->accepted())->toBeTrue()
        ->and($http->requests)->toHaveCount(2)
        ->and($http->requests[0]['url'])->toBe('https://api.ranetrace.com/v1/errors/store')
        ->and($http->requests[0]['headers'])->toBe($headers('Ranetrace-PHP/Errors/1.0'))
        ->and($http->requests[0]['timeout'])->toBe(10)
        ->and($http->requests[1]['url'])->toBe('https://api.ranetrace.com/v1/events/store')
        ->and($http->requests[1]['headers'])->toBe($headers('Ranetrace-PHP/Events/1.0'))
        ->and(array_keys($http->payload(0)))->toBe(['errors'])
        ->and($http->payload(0)['errors'])->toHaveCount(1)
        ->and(array_keys($http->payload(1)))->toBe(['events'])
        ->and($http->payload(1)['events'])->toHaveCount(1);

    $error = $http->payload(0)['errors'][0];
    $event = $http->payload(1)['events'][0];

    expect($error['message'])->toBe('Test exception from Ranetrace')
        ->and($error['type'])->toBe('Exception')
        ->and($event['event_name'])->toBe('test_event')
        ->and($event['properties'])->toBe(['source' => 'ranetrace-test'])
        ->and(DescriptorValidator::violations(WireContract::item('errors')['fields'], $error, true))->toBe([])
        ->and(DescriptorValidator::violations(WireContract::item('events')['fields'], sendTestAsReceived($event), true))->toBe([]);
});

it('renders the whole report in the documented layout', function (): void {
    $directory = tempDirectory();

    $output = sendTestSdk($directory, new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)))
        ->sendTest()
        ->render(fromEnvironment: true);

    expect($output)->toBe(<<<TEXT
        Ranetrace test

          Key      test... (RANETRACE_KEY)
          API      https://api.ranetrace.com/v1

          errors   accepted
          events   accepted

          Buffer   {$directory}
          Waiting  nothing
          Pauses   none

        Open your website in Ranetrace to see what was accepted.

        TEXT);
});

it('names the key by its config key when the host configured it', function (): void {
    $output = sendTestSdk(tempDirectory(), new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)))
        ->sendTest()
        ->render();

    expect($output)->toContain("  Key      test...\n")
        ->not->toContain('RANETRACE_KEY');
});

it('never shows more of the key than its first four characters', function (): void {
    $output = sendTestSdk(tempDirectory(), new FakeHttpClient, ['key' => 'abcdefghijklmnop'])
        ->sendTest()
        ->render(fromEnvironment: true);

    expect($output)->toContain('abcd...')
        ->not->toContain('abcde');
});

it('leaves the real spool as it found it, whatever the api answers', function (RawResponse $response): void {
    $directory = tempDirectory();
    $sdk = sendTestSdk($directory, new FakeHttpClient($response, $response));
    $sdk->buffer()->addItem('errors', ['message' => 'spooled error']);
    $sdk->buffer()->addItem('events', ['event_name' => 'spooled_event']);
    $before = sendTestSnapshot($directory);

    $sdk->sendTest();

    expect(sendTestSnapshot($directory))->toBe($before)
        ->and($sdk->buffer()->count('errors'))->toBe(1)
        ->and($sdk->buffer()->count('events'))->toBe(1)
        ->and(is_file($directory.'/pauses.json'))->toBeFalse()
        ->and(is_file($directory.'/state.json'))->toBeFalse();
})->with([
    'a 200' => [sendTestResponse(200)],
    'a 401' => [sendTestResponse(401, ['error' => ['message' => 'Invalid API key']])],
    'a network failure' => [RawResponse::transportFailure('Connection refused')],
    'a 500' => [sendTestResponse(500, [])],
]);

it('does not send the event once the key was refused for the error', function (): void {
    $http = new FakeHttpClient(sendTestResponse(401, ['error' => ['message' => 'Invalid API key']]), sendTestResponse(200));

    $report = sendTestSdk(tempDirectory(), $http)->sendTest();

    expect($http->requests)->toHaveCount(1)
        ->and($report->accepted())->toBeFalse()
        ->and($report->render())
        ->toContain('  errors   refused: the API answered 401 (Invalid API key). Check the configured key')
        ->toContain('  events   not sent: the key was refused')
        ->toContain("\nNothing was accepted.\n")
        ->and($report->render(fromEnvironment: true))->toContain('Check RANETRACE_KEY');
});

it('says a type is switched off rather than not sent after a 401', function (): void {
    $http = new FakeHttpClient(sendTestResponse(401, []));

    $output = sendTestSdk(tempDirectory(), $http, ['events' => ['enabled' => false]])->sendTest()->render();

    expect($http->requests)->toHaveCount(1)
        ->and($output)->toContain("  events   skipped: events.enabled is false\n");
});

it('falls back to Unauthorized when a 401 carries no message', function (): void {
    $report = sendTestSdk(tempDirectory(), new FakeHttpClient(sendTestResponse(401, '')))->sendTest();

    expect($report->render())->toContain('refused: the API answered 401 (Unauthorized).');
});

it('says what each answer means and whether it counts as accepted', function (RawResponse $response, string $errorsLine, string $eventsLine, bool $accepted): void {
    $report = sendTestSdk(tempDirectory(), new FakeHttpClient($response, $response))->sendTest();

    expect($report->render())
        ->toContain("  errors   {$errorsLine}\n")
        ->toContain("  events   {$eventsLine}\n")
        ->and($report->accepted())->toBe($accepted);
})->with([
    'a 403' => [
        sendTestResponse(403, ['error' => ['message' => 'Feature disabled']]),
        'refused: the API answered 403 (Feature disabled). The key lacks access to this feature, the website is in maintenance mode, or the account has no access',
        'refused: the API answered 403 (Feature disabled). The key lacks access to this feature, the website is in maintenance mode, or the account has no access',
        false,
    ],
    'a 429 with Retry-After' => [
        sendTestResponse(429, [], ['retry-after' => '30']),
        'rate limited: the API answered 429. Try again in 30 seconds',
        'rate limited: the API answered 429. Try again in 30 seconds',
        false,
    ],
    'a 429 without Retry-After' => [
        sendTestResponse(429, []),
        'rate limited: the API answered 429. Try again in 60 seconds',
        'rate limited: the API answered 429. Try again in 60 seconds',
        false,
    ],
    'no answer at all' => [
        RawResponse::transportFailure('Connection refused'),
        'failed: could not reach https://api.ranetrace.com/v1 (Connection refused)',
        'failed: could not reach https://api.ranetrace.com/v1 (Connection refused)',
        false,
    ],
    'a 500 with a message' => [
        sendTestResponse(500, ['error' => ['message' => 'Server Error']]),
        'failed: the API answered 500 (Server Error)',
        'failed: the API answered 500 (Server Error)',
        false,
    ],
    'a 502 without one' => [
        sendTestResponse(502, '<html>Bad gateway</html>'),
        'failed: the API answered 502 (no message)',
        'failed: the API answered 502 (no message)',
        false,
    ],
    'a 200 that ignored the item' => [
        sendTestResponse(200, ['success' => true, 'items' => ['received' => 1, 'processed' => 0, 'ignored' => 1]]),
        'accepted, not stored: the API stores the same error once per 5 minutes and skips an error you set to ignored',
        'accepted, not stored: the API ignored it',
        true,
    ],
    'a 200 that failed the item' => [
        sendTestResponse(200, ['success' => true, 'items' => ['received' => 1, 'processed' => 0, 'failed' => 1]]),
        'refused: the API did not store the test item. This is a bug in the SDK, please report it',
        'refused: the API did not store the test item. This is a bug in the SDK, please report it',
        false,
    ],
    'a 200 that ran out of time' => [
        sendTestResponse(200, ['success' => true, 'items' => ['received' => 1, 'processed' => 0, 'unprocessed' => 1], 'unprocessed_indexes' => [0]]),
        'not processed: the API ran out of time. Run the test again',
        'not processed: the API ran out of time. Run the test again',
        false,
    ],
    // A base URL that points at an ordinary website answers 200 with a page.
    'a 200 that is not json' => [
        sendTestResponse(200, '<html>Welcome</html>'),
        'failed: the API answered 200 without counting the test item, so https://api.ranetrace.com/v1 may not be the Ranetrace API',
        'failed: the API answered 200 without counting the test item, so https://api.ranetrace.com/v1 may not be the Ranetrace API',
        false,
    ],
    'a 200 that counts nothing' => [
        sendTestResponse(200, ['success' => true]),
        'failed: the API answered 200 without counting the test item, so https://api.ranetrace.com/v1 may not be the Ranetrace API',
        'failed: the API answered 200 without counting the test item, so https://api.ranetrace.com/v1 may not be the Ranetrace API',
        false,
    ],
]);

it('counts as accepted when one type was accepted and the other refused', function (): void {
    $report = sendTestSdk(tempDirectory(), new FakeHttpClient(sendTestResponse(403, []), sendTestResponse(200)))->sendTest();

    expect($report->accepted())->toBeTrue()
        ->and($report->render())
        ->toContain('  errors   refused: the API answered 403 (Forbidden).')
        ->toContain("  events   accepted\n")
        ->toContain("\nOpen your website in Ranetrace to see what was accepted.\n");
});

it('skips a type whose feature is off and still sends the other', function (string $off, string $sent, string $setting, string $variable): void {
    $http = new FakeHttpClient(sendTestResponse(200));

    $report = sendTestSdk(tempDirectory(), $http, [$off => ['enabled' => false]])->sendTest();

    expect($http->requests)->toHaveCount(1)
        ->and(array_keys($http->payload()))->toBe([$sent])
        ->and($report->accepted())->toBeTrue()
        ->and($report->render())->toContain("  {$off}   skipped: {$setting} is false\n")
        ->and($report->render(fromEnvironment: true))->toContain("  {$off}   skipped: {$variable} is false\n");
})->with([
    'errors off' => ['errors', 'events', 'errors.enabled', 'RANETRACE_ERRORS_ENABLED'],
    'events off' => ['events', 'errors', 'events.enabled', 'RANETRACE_EVENTS_ENABLED'],
]);

it('sends nothing without a key, and says why in words true for each surface', function (): void {
    $http = new FakeHttpClient;

    $report = sendTestSdk(tempDirectory(), $http, ['key' => '  '])->sendTest();

    expect($http->requests)->toBe([])
        ->and($report->accepted())->toBeFalse()
        ->and($report->render())
        ->toContain("  Key      not set\n")
        ->toContain("\n  No key is configured, so nothing is captured or sent.\n\n  Buffer")
        ->not->toContain('environment')
        ->toContain("\nNothing was accepted.\n")
        ->and($report->render(fromEnvironment: true))
        ->toContain("  Key      not set\n")
        ->toContain("  RANETRACE_KEY is not set in this command's environment, so nothing is captured or sent. This command reads the environment only: a key your application loads from a .env file or sets in its bootstrap does not reach it.\n");
});

it('sends nothing while the master switch is off', function (): void {
    $http = new FakeHttpClient;

    $report = sendTestSdk(tempDirectory(), $http, ['enabled' => false])->sendTest();

    expect($http->requests)->toBe([])
        ->and($report->accepted())->toBeFalse()
        ->and($report->render())->toContain("\n  The enabled setting is false, so nothing is captured or sent.\n")
        ->and($report->render(fromEnvironment: true))->toContain("\n  RANETRACE_ENABLED is false, so nothing is captured or sent.\n");
});

it('lifts a global pause when a 200 shows the key is accepted, and sends while it was active', function (): void {
    $directory = tempDirectory();
    $http = new FakeHttpClient(sendTestResponse(200), sendTestResponse(200));
    $sdk = sendTestSdk($directory, $http);
    $sdk->pauses()->pauseGlobal(900, '401');

    $output = $sdk->sendTest()->render();

    expect($http->requests)->toHaveCount(2)
        ->and($sdk->pauses()->isGloballyPaused())->toBeFalse()
        ->and($output)->toContain("\n  Waiting  nothing\n  Lifted   the pause on everything (after a 401): the key is accepted now\n  Pauses   none\n");
});

it('lifts the type\'s own pause that a 200 disproves', function (string $reason, string $wording): void {
    $sdk = sendTestSdk(tempDirectory(), new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)));
    $sdk->pauses()->pauseFeature('errors', 900, $reason);

    $output = $sdk->sendTest()->render();

    expect($sdk->pauses()->isFeaturePaused('errors'))->toBeFalse()
        ->and($output)->toContain("  Lifted   the pause on errors (after {$wording}): the errors endpoint answered 200 just now\n  Pauses   none\n");
})->with([
    'a network failure' => ['network', 'a network failure'],
    'a 403' => ['403', 'a 403'],
    'a 500' => ['500', 'a 500'],
]);

it('names every pause it lifted, one line each', function (): void {
    $sdk = sendTestSdk(tempDirectory(), new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)));
    $sdk->pauses()->pauseGlobal(900, '401');
    $sdk->pauses()->pauseFeature('errors', 900, 'network');

    expect($sdk->sendTest()->render())->toContain(
        "  Lifted   the pause on everything (after a 401): the key is accepted now\n"
        ."           the pause on errors (after a network failure): the errors endpoint answered 200 just now\n"
        ."  Pauses   none\n",
    );
});

it('keeps a pause one accepted item says nothing about', function (string $reason): void {
    $sdk = sendTestSdk(tempDirectory(), new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)));
    $sdk->pauses()->pauseFeature('errors', 900, $reason);

    $output = $sdk->sendTest()->render();

    expect($sdk->pauses()->featurePause('errors')['reason'] ?? null)->toBe($reason)
        ->and($output)->not->toContain('Lifted')
        ->and($output)->toContain("  Pauses   errors, for 15 more minutes (after a {$reason})\n");
})->with(['429', '413', '422']);

it('only reports a pause on a type the test does not send', function (): void {
    $sdk = sendTestSdk(tempDirectory(), new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)));
    $sdk->pauses()->pauseFeature('logs', 40, 'network');

    $output = $sdk->sendTest()->render();

    expect($sdk->pauses()->isFeaturePaused('logs'))->toBeTrue()
        ->and($output)->not->toContain('Lifted')
        ->and($output)->toMatch('/  Pauses   logs, for (39|40) more seconds \(after a network failure\)\n/');
});

it('does not let one type\'s 200 lift the other type\'s pause', function (): void {
    $sdk = sendTestSdk(tempDirectory(), new FakeHttpClient(sendTestResponse(200), sendTestResponse(500, [])));
    $sdk->pauses()->pauseFeature('events', 900, '403');

    $output = $sdk->sendTest()->render();

    expect($sdk->pauses()->featurePause('events')['reason'] ?? null)->toBe('403')
        ->and($output)->not->toContain('Lifted')
        ->and($output)->toContain("  Pauses   events, for 15 more minutes (after a 403)\n");
});

it('lifts nothing when no 200 came back', function (RawResponse $response): void {
    $sdk = sendTestSdk(tempDirectory(), new FakeHttpClient($response, $response));
    $sdk->pauses()->pauseGlobal(900, '401');
    $sdk->pauses()->pauseFeature('errors', 900, 'network');

    $output = $sdk->sendTest()->render();

    expect($sdk->pauses()->isGloballyPaused())->toBeTrue()
        ->and($sdk->pauses()->isFeaturePaused('errors'))->toBeTrue()
        ->and($output)->not->toContain('Lifted')
        ->and($output)->toContain(
            "  Pauses   everything, for 15 more minutes (after a 401)\n"
            ."           errors, for 15 more minutes (after a network failure)\n",
        );
})->with([
    'a 500' => [sendTestResponse(500, [])],
    'a network failure' => [RawResponse::transportFailure('Connection refused')],
    'a 200 that is not the api' => [sendTestResponse(200, '<html>Welcome</html>')],
]);

it('does not claim a pause was lifted when clearing it could not take the lock', function (): void {
    $directory = tempDirectory();
    $sdk = sendTestSdk($directory, new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)), ['batch' => ['lock_wait' => 0]]);
    $sdk->pauses()->pauseGlobal(900, '401');

    $lock = new FileLock($directory.'/pauses.lock', 0);
    $handle = $lock->acquire();

    try {
        $output = $sdk->sendTest()->render();
    } finally {
        $lock->release($handle);
    }

    expect($sdk->pauses()->isGloballyPaused())->toBeTrue()
        ->and($output)->not->toContain('Lifted')
        ->and($output)->toContain('  Pauses   everything, for 15 more minutes (after a 401)');
});

it('counts the items waiting, per type that holds any', function (): void {
    $sdk = sendTestSdk(tempDirectory(), new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)));

    foreach (['one', 'two', 'three'] as $message) {
        $sdk->buffer()->addItem('errors', ['message' => $message]);
    }

    $sdk->buffer()->addItem('events', ['event_name' => 'sale']);

    expect($sdk->sendTest()->render())->toContain("  Waiting  3 errors, 1 event\n");
});

/**
 * Spool one item of a type, captured the given number of seconds ago.
 */
function sendTestSeedOld(string $directory, string $type, int $age): void
{
    file_put_contents($directory.'/'.$type.'.json', (string) json_encode([
        ['id' => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'data' => ['message' => 'old'], 'timestamp' => time() - $age],
    ]));
}

it('says how long the oldest item has waited, and that nothing drained it when nothing is paused', function (): void {
    $directory = tempDirectory();
    sendTestSeedOld($directory, 'logs', 15 * 60 + 5);

    $output = sendTestSdk($directory, new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)))->sendTest()->render();

    expect($output)->toContain(
        "  Waiting  1 log record\n"
        ."           The oldest has waited 15 minutes. Nothing has drained the buffer in that time: check the cron line for vendor/bin/ranetrace-flush.\n",
    );
});

it('does not blame the cron line for a wait while a pause is active', function (): void {
    $directory = tempDirectory();
    sendTestSeedOld($directory, 'logs', 15 * 60 + 5);
    $sdk = sendTestSdk($directory, new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)));
    $sdk->pauses()->pauseFeature('logs', 900, '429');

    $output = $sdk->sendTest()->render();

    expect($output)->toContain("           The oldest has waited 15 minutes.\n")
        ->not->toContain('Nothing has drained');
});

it('says nothing about a wait under 10 minutes', function (): void {
    $directory = tempDirectory();
    sendTestSeedOld($directory, 'errors', 9 * 60);

    $output = sendTestSdk($directory, new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)))->sendTest()->render();

    expect($output)->toContain("  Waiting  1 error\n  Pauses   none\n")
        ->not->toContain('The oldest');
});

/**
 * Another user is emulated by taking this process's access away by mode, which
 * root ignores.
 */
function sendTestRunsAsRoot(): bool
{
    return ! function_exists('posix_geteuid') || posix_geteuid() === 0;
}

it('says when this user cannot use the buffer, without changing the exit state', function (): void {
    $directory = tempDirectory();
    touch($directory.'/errors.lock');
    chmod($directory.'/errors.lock', 0444);

    try {
        $report = sendTestSdk($directory, new FakeHttpClient(sendTestResponse(200), sendTestResponse(200)))->sendTest();
    } finally {
        chmod($directory.'/errors.lock', 0600);
    }

    expect($report->accepted())->toBeTrue()
        ->and($report->render())
        ->toContain("  Buffer   {$directory}\n           This user cannot use it: the lock file errors.lock is not writable. Run the cron flush as the user your web server runs as.\n  Pauses   none\n")
        ->not->toContain('Waiting');
})->skip(sendTestRunsAsRoot(...), 'root ignores file modes');

it('never throws when the transport throws', function (): void {
    $directory = tempDirectory();
    $http = new class extends FakeHttpClient
    {
        public function post(string $url, array $headers, string $body, int $connectTimeout, int $timeout): RawResponse
        {
            throw new RuntimeException('transport exploded');
        }
    };

    $report = sendTestSdk($directory, $http)->sendTest();

    expect($report->accepted())->toBeFalse()
        ->and($report->render())
        ->toContain('  errors   failed: could not reach https://api.ranetrace.com/v1 (transport exploded)')
        ->toContain('  events   failed: could not reach https://api.ranetrace.com/v1 (transport exploded)')
        ->and(is_file($directory.'/pauses.json'))->toBeFalse();
});

it('sends the same error on every run, so a second run within 5 minutes is the duplicate the api skips', function (): void {
    $first = new FakeHttpClient(sendTestResponse(200), sendTestResponse(200));
    $second = new FakeHttpClient(sendTestResponse(200), sendTestResponse(200));

    sendTestSdk(tempDirectory(), $first)->sendTest();
    sendTestSdk(tempDirectory(), $second)->sendTest();

    $error = $first->payload(0)['errors'][0];

    expect([$error['message'], $error['file'], $error['line']])
        ->toBe([$second->payload(0)['errors'][0]['message'], $second->payload(0)['errors'][0]['file'], $second->payload(0)['errors'][0]['line']])
        ->and($error['file'])->not->toStartWith('src/');
});

/**
 * The capture paths never fail on configuration alone, so a type whose capture
 * left no item is built directly rather than provoked.
 */
it('names the internal log when a type\'s test item could not be captured', function (string $log, string $line): void {
    $report = new TestReport(
        keyPreview: 'test...',
        baseUrl: 'https://api.ranetrace.com/v1',
        masterSwitchOn: true,
        types: ['errors' => TestResult::notCaptured($log)],
        bufferPath: '/var/spool/ranetrace',
        accessProblem: null,
        waiting: [],
        oldestWaitSeconds: null,
        lifted: [],
        pauses: [],
    );

    expect($report->accepted())->toBeFalse()
        ->and($report->render())->toContain("  errors   {$line}\n");
})->with([
    'with internal logging on' => [
        '/var/spool/ranetrace/internal-2026-11-12.log',
        'not captured: the SDK could not build the test item. The reason is in /var/spool/ranetrace/internal-2026-11-12.log',
    ],
    'with internal logging off' => [
        '',
        'not captured: the SDK could not build the test item. Turn internal logging on to see why',
    ],
]);
