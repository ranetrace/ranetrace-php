<?php

declare(strict_types=1);

use Ranetrace\Php\JavaScript\CaptureScript;

/*
 * The capture script ships as a committed pair: `resources/js/error-tracker.js`
 * is the readable source humans edit, `resources/js/error-tracker.min.js` is its
 * generated twin and the body `CaptureScript` inlines into a browser page.
 *
 * `JavaScriptCaptureScriptTest` guards the source, where the behaviour is written
 * and readable. These guard the twin, which is what a visitor actually runs, and
 * they are deliberately of two kinds.
 *
 * The freshness guards compare sha256 hashes against the stamp the build script
 * wrote, so they need no JavaScript toolchain: the suite runs everywhere, node
 * runs only on a maintainer's machine, and an edit to either file without a
 * rebuild fails here rather than shipping a stale script.
 *
 * The rest pin what minification must not take away. Every local name in the
 * source is renamed, so these key only on what survives: string literals,
 * property names, `window` members and the config keys.
 */

/**
 * @return array{source: string, minified: string, manifest: string}
 */
function capturePaths(): array
{
    $root = dirname(__DIR__, 2).'/resources/js';

    return [
        'source' => $root.'/error-tracker.js',
        'minified' => $root.'/error-tracker.min.js',
        'manifest' => $root.'/build-manifest.json',
    ];
}

/**
 * @return array{esbuild: string, command: string, rebuild_with: string, sha256: array<string, string>}
 */
function captureBuildManifest(): array
{
    return json_decode((string) file_get_contents(capturePaths()['manifest']), true, 512, JSON_THROW_ON_ERROR);
}

function minifiedCaptureScript(): string
{
    return (string) file_get_contents(capturePaths()['minified']);
}

test('the package ships the minified twin beside the readable source', function (): void {
    expect(capturePaths()['minified'])->toBeReadableFile()
        ->and(capturePaths()['manifest'])->toBeReadableFile();
});

/**
 * The stale-twin guard, and the reason the pair can be committed at all. A PHP
 * package is installed by Composer, which runs no JavaScript build, so the bytes
 * have to be in the repository; a hash comparison is what keeps them honest
 * without asking the suite for a toolchain.
 */
test('the minified twin was built from the source as it stands now', function (): void {
    expect(hash_file('sha256', capturePaths()['source']))
        ->toBe(captureBuildManifest()['sha256']['error-tracker.js'], <<<'MESSAGE'

        resources/js/error-tracker.js changed without a rebuild, so the minified
        twin the package actually ships is stale. Run:

            composer build-js

        MESSAGE);
});

/**
 * The stamp above compares the source, so on its own it says nothing about
 * someone hand-editing the generated file. This says it: the twin is only ever
 * the build script's output.
 */
test('the minified twin is exactly what the build wrote, never hand-edited', function (): void {
    expect(hash_file('sha256', capturePaths()['minified']))
        ->toBe(captureBuildManifest()['sha256']['error-tracker.min.js'], <<<'MESSAGE'

        resources/js/error-tracker.min.js is not the file the build wrote. It is
        generated; edit resources/js/error-tracker.js instead and run:

            composer build-js

        MESSAGE);
});

/**
 * A different esbuild version can emit different bytes for the same input, so the
 * version and the flags are part of the stamp rather than folklore in a commit
 * message.
 */
test('the manifest records the pinned toolchain that produced the twin', function (): void {
    $manifest = captureBuildManifest();

    expect($manifest['esbuild'])->toBe('0.28.2')
        ->and($manifest['rebuild_with'])->toBe('composer build-js')
        ->and($manifest['command'])
        ->toContain('--minify')
        ->toContain('--target=es2020')
        ->toContain('--legal-comments=none');
});

test('the twin is a fraction of the source it was built from', function (): void {
    expect(filesize(capturePaths()['minified']))->toBeLessThan(filesize(capturePaths()['source']) / 2);
});

/**
 * Minification may not quote, split or fold the token into another expression:
 * the JSON is substituted textually, so it has to land as a bare assignment
 * right-hand side or every page of every consuming site gets a syntax error.
 */
test('the token survives minification exactly once, as a bare assignment', function (): void {
    $minified = minifiedCaptureScript();
    $at = mb_strpos($minified, CaptureScript::CONFIG_TOKEN);

    expect(mb_substr_count($minified, CaptureScript::CONFIG_TOKEN))->toBe(1)
        ->and(mb_substr($minified, $at - 1, 1))->toBe('=')
        ->and(mb_substr($minified, $at + mb_strlen(CaptureScript::CONFIG_TOKEN), 1))->toBe(';');
});

/**
 * The whole point of the twin: these bytes are inlined into every page view of
 * every site that installs either SDK, so a comment here is downloaded by every
 * visitor on the critical path of a page they are waiting for.
 */
test('the twin ships no comments to a browser', function (string $marker): void {
    expect(minifiedCaptureScript())->not->toContain($marker);
})->with(['/*', '*/', '<!--']);

test('the twin ships no line comments either', function (): void {
    expect(preg_match('#(^|\n)[ \t]*//#', minifiedCaptureScript()))->toBe(0);
});

test('a rendered script carries no comment the readable source has', function (): void {
    expect(CaptureScript::withConfig(['enabled' => true]))
        ->not->toContain('Ranetrace JavaScript Error Tracking')
        ->not->toContain('Error deduplication');
});

/**
 * The behaviour guards, re-keyed off everything minification renames. Each marker
 * below is the minified spelling of an assertion `JavaScriptCaptureScriptTest`
 * makes against the source, and together they are what the relay depends on
 * reaching it.
 */
test('the twin still carries the behaviour the relay depends on', function (string $marker): void {
    expect(minifiedCaptureScript())->toContain($marker);
})->with([
    // Both listeners, the error one in the capture phase (`true` minifies to `!0`).
    'error listener in the capture phase' => ['window.addEventListener("error",'],
    'rejection listener' => ['window.addEventListener("unhandledrejection",'],
    // The two headers every host sends, and the third only Laravel configures.
    'content type header' => ['"Content-Type":"application/json"'],
    'requested with header' => ['"X-Requested-With"]="XMLHttpRequest"'],
    'csrf header behind its config flag' => ['.csrfToken&&'],
    'csrf header value' => ['"X-CSRF-TOKEN"]'],
    // The seven browser-info fields the relay rebuilds are property names, which
    // are never renamed.
    'browser info' => ['screen_width:'],
    'connection type' => ['connection_type:'],
    // A failed send is warned about, never rethrown.
    'silent failure' => ['console.warn("Failed to send error to Ranetrace:"'],
    // The breadcrumb sources, each identified by its two string literals.
    'navigation breadcrumb' => ['"navigation","Page loaded"'],
    'click breadcrumb' => ['"user","Click"'],
    'form breadcrumb' => ['"user","Form submitted"'],
    'xhr breadcrumb' => ['"http","XHR completed"'],
    'fetch breadcrumb' => ['"http","Fetch completed"'],
    'xhr instrumentation' => ['_ranetrace_method'],
    // Console interception and its item type.
    'console error type' => ['"ConsoleError"'],
    'console error prefix' => ['"Console Error: "'],
    // The rejection defaults.
    'rejection message default' => ['"Unhandled Promise Rejection"'],
    'rejection type default' => ['"UnhandledRejection"'],
    // The manual capture API, on window, so its names survive.
    'manual capture' => ['window.Ranetrace.captureError='],
    'manual breadcrumb' => ['window.Ranetrace.addBreadcrumb='],
    // The keepalive ladder's two outcomes.
    'keepalive on' => ['keepalive:!0'],
    'keepalive off' => ['keepalive:!1'],
]);

/**
 * The config keys are how a host talks to the script. They are property reads, so
 * minification keeps them, and a rename here would silently disable a feature
 * rather than fail.
 */
test('the twin still reads every config key a host supplies', function (string $key): void {
    expect(minifiedCaptureScript())->toContain('.'.$key);
})->with([
    'enabled',
    'endpoint',
    'sampleRate',
    'captureConsoleErrors',
    'maxBreadcrumbs',
    'ignoredErrors',
    'csrfToken',
]);

/**
 * A config value carries whatever a host puts in it. `CaptureScript::encode()`
 * sets JSON_HEX_TAG/AMP/APOS for exactly this, and the proof belongs on the file
 * that ships rather than on the readable source.
 */
test('a hostile config still yields one valid script', function (): void {
    $rendered = CaptureScript::withConfig(hostileCaptureConfig());

    expect($rendered)
        ->not->toContain(CaptureScript::CONFIG_TOKEN)
        ->not->toContain('</script>')
        ->not->toContain('&quot;')
        ->and(capturedScriptConfig($rendered))->toBe(hostileCaptureConfig());
});

/**
 * And that it parses. The build script runs this check too, where node is
 * guaranteed to be present because esbuild just ran; here it is opportunistic, so
 * a machine without node still gets the structural guard above.
 */
test('a hostile config leaves the rendered script parseable javascript', function (): void {
    $path = (string) tempnam(sys_get_temp_dir(), 'ranetrace-capture-').'.js';
    file_put_contents($path, CaptureScript::withConfig(hostileCaptureConfig()));

    exec('node --check '.escapeshellarg($path).' 2>&1', $output, $status);
    @unlink($path);

    expect($status)->toBe(0, implode("\n", $output));
})->skip(
    mb_trim((string) shell_exec('command -v node 2>/dev/null')) === '',
    'node is not on PATH. bin/build-capture-script runs the same check where node is guaranteed.',
);

/**
 * Everything a config value can carry that could break the literal or the tag
 * around it: quotes, a backslash, a closing script tag, a newline, non-ASCII, the
 * two line separators that only ES2019 and later allow raw inside a string
 * literal (the es2020 target already requires them), and nesting.
 *
 * @return array<string, mixed>
 */
function hostileCaptureConfig(): array
{
    return [
        'endpoint' => '/ranetrace/js-errors?a=1&b=2',
        'enabled' => true,
        'csrfToken' => 'quote " apostrophe \' backslash \\ tag </script><script>alert(1)</script>',
        'ignoredErrors' => ['naïve 日本語 🙂', '</script>', "line\nbreak", "separator \u{2028}\u{2029}"],
        'nested' => [['deep' => [1, 2, ['deeper' => null, 'empty' => []]]]],
    ];
}
