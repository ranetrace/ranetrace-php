<?php

declare(strict_types=1);

use Ranetrace\Php\Logging\LogItemBuilder;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;

function logItem(array $context = [], array $extra = [], array|callable|null $sensitivePathValues = null): array
{
    $config = testConfig();

    return (new LogItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))->build(
        'error',
        'Reset mail sent',
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
