<?php

declare(strict_types=1);

use Ranetrace\Php\JavaScript\ErrorItemBuilder;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;

/**
 * A browser report arrives as JSON, which has no spelling for INF or NAN, but
 * the relay takes the decoded array from its host, so a host that builds or
 * enriches one in PHP can hand it a float JSON cannot encode. The JavaScript
 * error builder's free-shape fields get the same string spelling as a log
 * context or an event property.
 */
test('a JavaScript error with a non-finite float in its context and breadcrumb data is built encodable', function (): void {
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    $item = (new ErrorItemBuilder($config, new SecretScrubber($config, new InternalLogger($config))))->build([
        'message' => 'Chart failed',
        'url' => 'https://example.test/report',
        'context' => ['ratio' => INF],
        'breadcrumbs' => [
            ['timestamp' => '2026-10-05T10:00:00Z', 'category' => 'ui', 'message' => 'zoom', 'data' => ['scale' => NAN]],
        ],
    ], null, null, null);

    expect($item['context'])->toBe(['ratio' => 'INF'])
        ->and($item['breadcrumbs'][0]['data'])->toBe(['scale' => 'NAN'])
        ->and(json_encode($item))->not->toBeFalse();
});
