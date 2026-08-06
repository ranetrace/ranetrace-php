<?php

declare(strict_types=1);

use Ranetrace\Php\Support\InternalLogger;

function loggerIn(string $directory, array $overrides = []): InternalLogger
{
    return new InternalLogger(testConfig(array_replace(['buffer_path' => $directory], $overrides)));
}

function logContents(string $directory): string
{
    $files = glob($directory.'/internal-*.log') ?: [];

    return $files === [] ? '' : (string) file_get_contents($files[0]);
}

/**
 * Point PHP's `error_log()` at a file for the duration of one test so the
 * stderr fallback can be observed instead of leaking into the test output.
 */
function captureErrorLog(): string
{
    $path = tempDirectory().'/error.log';

    ini_set('error_log', $path);

    return $path;
}

test('it writes the level, the message and the context to a daily file', function (): void {
    $directory = tempDirectory();

    loggerIn($directory)->error('Batch send failed', ['status' => 500]);

    expect(is_file($directory.'/internal-'.date('Y-m-d').'.log'))->toBeTrue()
        ->and(logContents($directory))->toContain('ERROR')
        ->toContain('Batch send failed')
        ->toContain('"status":500');
});

test('it creates the buffer directory when it does not exist yet', function (): void {
    $directory = tempDirectory().'/nested/deeper';

    loggerIn($directory)->info('hello');

    expect(is_dir($directory))->toBeTrue()
        ->and(logContents($directory))->toContain('hello');
});

test('it writes every severity through its named method', function (): void {
    $directory = tempDirectory();
    $logger = loggerIn($directory);

    $logger->debug('a');
    $logger->info('b');
    $logger->notice('c');
    $logger->warning('d');
    $logger->error('e');
    $logger->critical('f');

    expect(logContents($directory))
        ->toContain('DEBUG')->toContain('INFO')->toContain('NOTICE')
        ->toContain('WARNING')->toContain('ERROR')->toContain('CRITICAL');
});

test('records below the configured minimum level are dropped', function (): void {
    $directory = tempDirectory();
    $logger = loggerIn($directory, ['internal_logging' => ['level' => 'warning']]);

    $logger->debug('dropped debug');
    $logger->info('dropped info');
    $logger->warning('kept warning');
    $logger->critical('kept critical');

    expect(logContents($directory))
        ->not->toContain('dropped')
        ->toContain('kept warning')
        ->toContain('kept critical');
});

test('an unknown level is dropped rather than written', function (): void {
    $directory = tempDirectory();

    loggerIn($directory)->log('shout', 'nope');

    expect(logContents($directory))->toBe('');
});

test('nothing is written while internal logging is disabled', function (): void {
    $directory = tempDirectory();

    loggerIn($directory, ['internal_logging' => ['enabled' => false]])->error('silenced');

    expect(glob($directory.'/internal-*.log'))->toBe([]);
});

test('it falls back to stderr when the log file cannot be written', function (): void {
    $errorLog = captureErrorLog();

    // A path under a regular file can never become a directory.
    $blocked = tempDirectory().'/not-a-directory';
    file_put_contents($blocked, 'x');

    loggerIn($blocked.'/buffer')->error('unwritable sink', ['status' => 0]);

    expect((string) file_get_contents($errorLog))
        ->toContain('[Ranetrace Internal ERROR]')
        ->toContain('unwritable sink')
        ->toContain('"status":0');
});

test('the stderr fallback can be switched off entirely', function (): void {
    $errorLog = captureErrorLog();

    $blocked = tempDirectory().'/not-a-directory';
    file_put_contents($blocked, 'x');

    loggerIn($blocked.'/buffer', ['internal_logging' => ['stderr_fallback' => false]])->error('stays quiet');

    expect(is_file($errorLog) ? (string) file_get_contents($errorLog) : '')->not->toContain('stays quiet');
});

test('it prunes day files older than the retention window', function (): void {
    $directory = tempDirectory();

    file_put_contents($directory.'/internal-2000-01-01.log', 'ancient');
    file_put_contents($directory.'/internal-'.date('Y-m-d', strtotime('-2 days')).'.log', 'recent');
    file_put_contents($directory.'/unrelated.log', 'keep me');

    loggerIn($directory, ['internal_logging' => ['days' => 14]])->info('today');

    expect(is_file($directory.'/internal-2000-01-01.log'))->toBeFalse()
        ->and(is_file($directory.'/internal-'.date('Y-m-d', strtotime('-2 days')).'.log'))->toBeTrue()
        ->and(is_file($directory.'/unrelated.log'))->toBeTrue()
        ->and(is_file($directory.'/internal-'.date('Y-m-d').'.log'))->toBeTrue();
});

test('retention is skipped when the configured window is not positive', function (): void {
    $directory = tempDirectory();

    file_put_contents($directory.'/internal-2000-01-01.log', 'ancient');

    loggerIn($directory, ['internal_logging' => ['days' => 0]])->info('today');

    expect(is_file($directory.'/internal-2000-01-01.log'))->toBeTrue();
});

test('it never throws, whatever the sink does', function (): void {
    captureErrorLog();

    $logger = loggerIn('/dev/null/impossible');

    $logger->critical('still fine', ['nested' => ['deep' => true]]);

    expect(true)->toBeTrue();
});

test('currentLogFile names the day file inside the buffer directory', function (): void {
    $directory = tempDirectory();

    expect(loggerIn($directory)->currentLogFile(new DateTimeImmutable('2026-08-06 12:00:00')))
        ->toBe($directory.'/internal-2026-08-06.log');
});
