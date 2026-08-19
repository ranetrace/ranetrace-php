<?php

declare(strict_types=1);

/**
 * There is no JavaScript test runner in this package, so the capture script is
 * guarded from here instead. These assertions are not style checks: each one
 * pins a behaviour the relay depends on, so a refactor that quietly drops one
 * fails here rather than in a customer's browser.
 */
function captureScript(): string
{
    return (string) file_get_contents(dirname(__DIR__, 2).'/resources/js/error-tracker.js');
}

test('the template exposes exactly one config token for the snippet to replace', function (): void {
    expect(mb_substr_count(captureScript(), '__RANETRACE_CONFIG__'))->toBe(1)
        ->and(captureScript())->toContain('const config = __RANETRACE_CONFIG__;');
});

test('it registers both capture listeners, the error one in the capture phase', function (): void {
    expect(captureScript())
        ->toContain("window.addEventListener('error', function(event) {")
        ->toContain("window.addEventListener('unhandledrejection', function(event) {")
        ->toContain('    }, true);');
});

test('the deduplication key is built from message, filename, line and column', function (): void {
    expect(captureScript())->toContain('return `${message}|${filename}|${line}|${column}`;');
});

test('the ring buffer and dedup caches keep their agreed limits', function (): void {
    expect(captureScript())
        ->toContain('const ERROR_CACHE_SIZE = 50;')
        ->toContain('const KEEPALIVE_SIZE_LIMIT = 60000;')
        ->toContain('if (breadcrumbs.length > config.maxBreadcrumbs) {');
});

test('it posts with the two headers every host sends', function (): void {
    expect(captureScript())
        ->toContain("'Content-Type': 'application/json'")
        ->toContain("requestHeaders['X-Requested-With'] = 'XMLHttpRequest';")
        ->toContain('headers: requestHeaders,');
});

/**
 * The header is in the shared script so the Laravel SDK, whose relay sits behind
 * CSRF middleware, can keep sending it. It must stay behind the config flag: this
 * SDK's relay does a same-origin check instead and configures no token, and an
 * unconditional `X-CSRF-TOKEN: undefined` would be a header it never sent before.
 */
test('the csrf header is sent only when the host configured a token', function (): void {
    $script = captureScript();

    $guard = mb_strpos($script, 'if (config.csrfToken) {');
    $header = mb_strpos($script, "requestHeaders['X-CSRF-TOKEN'] = config.csrfToken;");

    expect($guard)->toBeInt()
        ->and($header)->toBeGreaterThan($guard)
        ->and(mb_substr_count($script, 'X-CSRF-TOKEN'))->toBe(2);
});

test('a failed send is warned about, never rethrown', function (): void {
    expect(captureScript())->toContain("console.warn('Failed to send error to Ranetrace:', err);");
});

test('it records all five breadcrumb sources', function (string $marker): void {
    expect(captureScript())->toContain($marker);
})->with([
    ["addBreadcrumb('navigation', 'Page loaded', {"],
    ["addBreadcrumb('user', 'Click', {"],
    ["addBreadcrumb('user', 'Form submitted', {"],
    ["addBreadcrumb('http', 'XHR completed', {"],
    ["addBreadcrumb('http', 'XHR failed', {"],
    ["addBreadcrumb('http', 'Fetch completed', {"],
    ["addBreadcrumb('http', 'Fetch failed', {"],
]);

test('browser info reports the seven fields the relay rebuilds', function (string $field): void {
    expect(captureScript())->toContain($field.':');
})->with([
    'screen_width',
    'screen_height',
    'viewport_width',
    'viewport_height',
    'device_memory',
    'hardware_concurrency',
    'connection_type',
]);

test('the keepalive trim ladder keeps its three rungs in order', function (): void {
    $script = captureScript();

    $breadcrumbTrim = mb_strpos($script, 'errorData.breadcrumbs.length / 2');
    $contextDrop = mb_strpos($script, 'errorData.context = {};');
    $giveUp = mb_strpos($script, 'return { body: body, keepalive: false };');

    expect($breadcrumbTrim)->toBeInt()
        ->and($contextDrop)->toBeGreaterThan($breadcrumbTrim)
        ->and($giveUp)->toBeGreaterThan($contextDrop);
});

test('console error interception stays behind its config flag', function (): void {
    expect(captureScript())->toContain('if (config.captureConsoleErrors) {')
        ->toContain("message: 'Console Error: ' + message,")
        ->toContain("type: 'ConsoleError',");
});

test('it exposes the manual capture api', function (): void {
    expect(captureScript())
        ->toContain('window.Ranetrace.captureError = function(error, context) {')
        ->toContain('window.Ranetrace.addBreadcrumb = addBreadcrumb;');
});

test('an unhandled rejection unwraps its reason with the documented defaults', function (): void {
    expect(captureScript())
        ->toContain("let message = 'Unhandled Promise Rejection';")
        ->toContain("let type = 'UnhandledRejection';")
        ->toContain('if (reason instanceof Error) {');
});
