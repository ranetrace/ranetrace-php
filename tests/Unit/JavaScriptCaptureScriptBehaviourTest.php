<?php

declare(strict_types=1);

use Ranetrace\Php\JavaScript\CaptureScript;

/*
 * `JavaScriptCaptureScriptTest` and `JavaScriptCaptureScriptBuildTest` read the
 * script's text, which proves a line is there and not what it does: a guard can
 * be present in the source and still never fire. These run the script that
 * ships, the minified twin as `CaptureScript` renders it, in node against a
 * stand-in page (tests/Doubles/browser.js), fire `error` events at it and look at
 * what it posted.
 *
 * They need node, which the suite otherwise does not, so they skip without it,
 * like the syntax check in `JavaScriptCaptureScriptBuildTest`. The text guards in
 * those two files cover the same behaviour on a machine that has none.
 */

/**
 * The reports the shipped script posts when a page fires these `error` events.
 *
 * Nothing is on the ignore list, so a report that stays away was dropped by the
 * script itself and not by a pattern.
 *
 * @param  list<array<string, mixed>>  $events  `target` is "window" or "element".
 * @return list<array<string, mixed>>
 */
function reportsPostedFor(array $events): array
{
    $script = tempDirectory('ranetrace-capture-').'/capture.js';

    file_put_contents($script, CaptureScript::withConfig([
        'endpoint' => '/ranetrace/js-errors',
        'enabled' => true,
        'sampleRate' => 1.0,
        'captureConsoleErrors' => false,
        'maxBreadcrumbs' => 20,
        'ignoredErrors' => [],
    ]));

    exec(implode(' ', array_map(escapeshellarg(...), [
        'node',
        dirname(__DIR__).'/Doubles/browser.js',
        $script,
        json_encode($events, JSON_THROW_ON_ERROR),
    ])).' 2>&1', $output, $status);

    expect($status)->toBe(0, implode("\n", $output));

    return json_decode(implode("\n", $output), true, 512, JSON_THROW_ON_ERROR);
}

beforeEach(function (): void {
    if (mb_trim((string) shell_exec('command -v node 2>/dev/null')) === '') {
        $this->markTestSkipped('node is not on PATH. The text guards in JavaScriptCaptureScriptTest and JavaScriptCaptureScriptBuildTest still run.');
    }
});

/**
 * A blocked tag manager script or a broken image fires an `error` event on its
 * element with no message, file, line or error object. Posted, each one would be
 * an error named "Unknown error", with nothing in it to act on.
 */
test('a resource that failed to load is not reported', function (): void {
    expect(reportsPostedFor([['target' => 'element']]))->toBe([]);
});

test('a script error is reported with its message, place, type and stack', function (): void {
    $reports = reportsPostedFor([[
        'target' => 'window',
        'message' => 'Uncaught TypeError: cart.total is not a function',
        'filename' => 'https://shop.test/build/app.js',
        'lineno' => 12,
        'colno' => 5,
        'error' => ['name' => 'TypeError', 'message' => 'cart.total is not a function'],
    ]]);

    expect($reports)->toHaveCount(1)
        ->and($reports[0])->toMatchArray([
            'message' => 'Uncaught TypeError: cart.total is not a function',
            'filename' => 'https://shop.test/build/app.js',
            'line' => 12,
            'column' => 5,
            'type' => 'TypeError',
            'url' => 'https://shop.test/checkout',
        ])
        ->and($reports[0]['stack'])->toContain('cart.total is not a function');
});

test('a script error after a failed resource load is still reported', function (): void {
    $reports = reportsPostedFor([
        ['target' => 'element'],
        ['target' => 'window', 'message' => 'Uncaught ReferenceError: gtag is not defined'],
    ]);

    expect(array_column($reports, 'message'))->toBe(['Uncaught ReferenceError: gtag is not defined']);
});

/**
 * What tells a resource failure from a script error is where the event was
 * fired, not what it carries: a page or a library can dispatch its own event at
 * an element and put a message in it.
 */
test('an error event fired on an element is not reported, whatever it carries', function (): void {
    expect(reportsPostedFor([[
        'target' => 'element',
        'message' => 'The image could not be decoded',
        'error' => ['name' => 'Error', 'message' => 'The image could not be decoded'],
    ]]))->toBe([]);
});

test('an error event with nothing to say is not reported under a made-up name', function (): void {
    expect(reportsPostedFor([['target' => 'window']]))->toBe([]);
});

test('an error event without a message of its own takes the message of its error', function (): void {
    $reports = reportsPostedFor([[
        'target' => 'window',
        'error' => ['name' => 'RangeError', 'message' => 'Invalid array length'],
    ]]);

    expect($reports)->toHaveCount(1)
        ->and($reports[0])->toMatchArray(['message' => 'Invalid array length', 'type' => 'RangeError']);
});
