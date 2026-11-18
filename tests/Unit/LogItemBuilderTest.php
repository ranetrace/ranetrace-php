<?php

declare(strict_types=1);

use Ranetrace\Php\Logging\LogItemBuilder;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;

function logItem(array $context = [], array $extra = [], array|callable|null $sensitivePathValues = null, string $message = 'Reset mail sent'): array
{
    $config = testConfig();

    return (new LogItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))->build(
        'error',
        $message,
        $context,
        'stack',
        '2026-08-19T10:00:00+00:00',
        $extra,
        $sensitivePathValues,
    );
}

test('a log record scrubs the query of a url in its context whatever the host can say about paths', function (): void {
    expect(logItem(['endpoint' => 'https://api.test/hook?api_key=sk_live_x&page=2'])['context'])
        ->toBe(['endpoint' => 'https://api.test/hook?api_key=[REDACTED]&page=2']);
});

test('the path of a url in log context is left alone when the host cannot name its secret segments', function (): void {
    // A plain PHP host has no router. Query-only is the honest answer, not a
    // guess at which segment is a token.
    expect(logItem(['link' => 'https://api.test/reset-password/live-token'])['context'])
        ->toBe(['link' => 'https://api.test/reset-password/live-token']);
});

test('a host that can name them has them redacted, per url, in context and in extra', function (): void {
    // Log context is free-form and carries URLs from requests other than the
    // one being handled, so the host answers per URL. This is the seam the
    // Laravel SDK fills with its router; without it, a reset link logged
    // alongside the mail it went into keeps its live token.
    $resolver = fn (string $url): array => str_contains($url, '/reset-password/') ? ['live-token'] : [];

    $item = logItem(
        ['link' => 'https://api.test/reset-password/live-token', 'home' => 'https://api.test/dashboard'],
        ['referer' => 'https://api.test/reset-password/live-token'],
        $resolver,
    );

    expect($item['context'])->toBe([
        'link' => 'https://api.test/reset-password/[REDACTED]',
        'home' => 'https://api.test/dashboard',
    ])->and($item['extra']['referer'])->toBe('https://api.test/reset-password/[REDACTED]');
});

test('a fixed list of sensitive values applies to every url in the record', function (): void {
    expect(logItem(['link' => 'https://api.test/reset-password/live-token'], [], ['live-token'])['context'])
        ->toBe(['link' => 'https://api.test/reset-password/[REDACTED]']);
});

/**
 * A failed job is logged with its exception, and the string form of an
 * exception holds its message, its trace and those of every exception before
 * it.
 */
test('a logged exception whose message holds a telegram api url loses the bot token everywhere', function (): void {
    $secret = implode('', ['AAF4k3T0ken', 'F4k3T0kenF4k3T0ken_F4k-3']);
    $url = 'https://api.telegram.org/bot123456789:'.$secret.'/sendMessage';
    $exception = new RuntimeException('The communication with Telegram failed. `POST '.$url.'`', 0, new LogicException('cURL error 28 for '.$url));

    $item = logItem(
        ['exception' => (string) $exception, 'request' => ['url' => $url]],
        ['previous' => $exception->getPrevious()->getMessage()],
        message: $exception->getMessage(),
    );

    expect($item['message'])->toBe('The communication with Telegram failed. `POST https://api.telegram.org/bot[REDACTED]/sendMessage`')
        ->and($item['context']['request']['url'])->toBe('https://api.telegram.org/bot[REDACTED]/sendMessage')
        ->and($item['context']['exception'])->toContain('cURL error 28 for https://api.telegram.org/bot[REDACTED]/sendMessage')
        ->and($item['extra']['previous'])->toBe('cURL error 28 for https://api.telegram.org/bot[REDACTED]/sendMessage')
        ->and((string) json_encode($item))->not->toContain($secret);
});

test('a log record names a file under the project root by its relative path, in its message, context and extra', function (): void {
    // A logged throwable is the usual carrier: Monolog hands it over as an
    // object, and its string form holds the file and the whole text trace.
    $config = testConfig(['project_root' => '/var/www/app']);
    $exception = new RuntimeException('Could not read /var/www/app/storage/import.csv');

    $item = (new LogItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))->build(
        'error',
        'Import failed for /var/www/app/storage/import.csv',
        ['file' => '/var/www/app/storage/import.csv', 'exception' => $exception, 'rows' => 12],
        'stack',
        '2026-08-19T10:00:00+00:00',
        ['script' => '/var/www/app/artisan'],
    );

    expect($item['message'])->toBe('Import failed for storage/import.csv')
        ->and($item['context']['file'])->toBe('storage/import.csv')
        ->and($item['context']['exception'])->toStartWith('RuntimeException: Could not read storage/import.csv in ')
        ->and($item['context']['rows'])->toBe(12)
        ->and($item['extra']['script'])->toBe('artisan')
        ->and(json_encode($item, JSON_UNESCAPED_SLASHES))->not->toContain('/var/www/app');
});

test('a project root holding an invalid byte is still taken off the message, the context and the extra', function (): void {
    // A path names the root in the same raw bytes the configured root holds.
    // Repaired first, the path holds U+FFFD where the root holds the byte, and
    // the two no longer match.
    $config = testConfig(['project_root' => "/srv/caf\xB1/app"]);

    $item = (new LogItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))->build(
        'error',
        "Import failed for /srv/caf\xB1/app/storage/import.csv",
        ['file' => "/srv/caf\xB1/app/storage/import.csv", 'nested' => ['script' => "/srv/caf\xB1/app/artisan"]],
        'stack',
        '2026-08-19T10:00:00+00:00',
        ['script' => "/srv/caf\xB1/app/artisan"],
    );

    expect($item['message'])->toBe('Import failed for storage/import.csv')
        ->and($item['context'])->toBe(['file' => 'storage/import.csv', 'nested' => ['script' => 'artisan']])
        ->and($item['extra']['script'])->toBe('artisan')
        ->and(json_encode($item, JSON_UNESCAPED_SLASHES))->not->toContain('/srv/caf');
});

test('an invalid byte outside the project root is still repaired once the root is off', function (): void {
    $config = testConfig(['project_root' => "/srv/caf\xB1/app"]);

    $item = (new LogItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))->build(
        'error',
        "Bad \xB1 byte in /srv/caf\xB1/app/data.csv",
        ["key\xB1" => "Bad \xB1 byte in /srv/caf\xB1/app/data.csv"],
        'stack',
        '2026-08-19T10:00:00+00:00',
        ['note' => "Bad \xB1 byte"],
    );

    expect($item['message'])->toBe("Bad \u{FFFD} byte in data.csv")
        ->and($item['context'])->toBe(["key\u{FFFD}" => "Bad \u{FFFD} byte in data.csv"])
        ->and($item['extra']['note'])->toBe("Bad \u{FFFD} byte")
        ->and(json_encode($item))->not->toBeFalse();
});

test('a root strip that cannot run costs the strip, never the log record or its secret scrub', function (): void {
    $config = testConfig(['project_root' => uncompilableRoot(), 'internal_logging' => ['enabled' => false]]);
    $builder = new LogItemBuilder($config, new SecretScrubber($config, new InternalLogger($config)));

    set_error_handler(static function (int $level, string $message): never {
        throw new ErrorException($message, 0, $level);
    });

    try {
        $item = $builder->build('error', 'Import of /var/www/app/a.csv failed for token=abc123', ['file' => '/var/www/app/a.csv'], 'stack', '2026-08-19T10:00:00+00:00', []);
    } finally {
        restore_error_handler();
    }

    expect($item['message'])->toBe('Import of /var/www/app/a.csv failed for token=[REDACTED]')
        ->and($item['context'])->toBe(['file' => '/var/www/app/a.csv']);
});
