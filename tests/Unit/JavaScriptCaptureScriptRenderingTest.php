<?php

declare(strict_types=1);

use Ranetrace\Php\JavaScript\CaptureScript;

/**
 * `CaptureScript` is the seam both SDKs render the shared browser script through.
 * `JavaScriptCaptureScriptTest` guards the readable source and
 * `JavaScriptCaptureScriptBuildTest` the minified twin it ships; these guard the
 * substitution, which is the part a consuming host depends on.
 *
 * What `withConfig()` returns is the minified twin, so nothing here may key on a
 * local name or on the source's formatting: both are gone. The config literal is
 * found through `capturedScriptConfig()`, and the assertions below stand on the
 * substituted JSON itself, which is this class's own output and untouched by the
 * minifier.
 */
test('it substitutes the config token completely', function (): void {
    $script = CaptureScript::withConfig(['endpoint' => '/e', 'enabled' => true]);

    expect($script)->not->toContain('__RANETRACE_CONFIG__')
        ->and($script)->toContain('{"endpoint":"/e","enabled":true}')
        ->and(capturedScriptConfig($script))->toBe(['endpoint' => '/e', 'enabled' => true]);
});

test('it returns the bare script body, leaving the script tag to the host', function (): void {
    $script = mb_trim(CaptureScript::withConfig(['enabled' => true]));

    expect($script)->not->toStartWith('<script')
        ->not->toEndWith('</script>')
        // A self-contained IIFE in strict mode, which is what a host can inline
        // anywhere without it leaking a name into the page.
        ->toStartWith('(function()')
        ->toContain('"use strict"')
        ->toEndWith('})();');
});

/**
 * The whole point of the shared class: a host may put anything the script reads
 * into the config, including a key the other host has no notion of. Laravel needs
 * `csrfToken`; a plain-PHP host omits it and the header is never sent.
 */
test('a host-specific config key is carried through untouched', function (): void {
    $script = CaptureScript::withConfig(['enabled' => true, 'csrfToken' => 'laravel-token']);

    expect(capturedScriptConfig($script))->toBe(['enabled' => true, 'csrfToken' => 'laravel-token']);
});

test('a sample rate of 1.0 stays spelled as a float', function (): void {
    expect(CaptureScript::withConfig(['sampleRate' => 1.0]))->toContain('{"sampleRate":1.0}');
});

test('a closing script tag inside a config value cannot terminate the host tag early', function (): void {
    $script = CaptureScript::withConfig(['ignoredErrors' => ['</script><script>alert(1)</script>']]);

    expect($script)->not->toContain('</script>')
        ->and(capturedScriptConfig($script)['ignoredErrors'])->toBe(['</script><script>alert(1)</script>']);
});

/**
 * JSON_HEX_QUOT must stay unset: it would escape the structural double quotes of
 * the object literal too, and `&quot;` outside a string is not valid JavaScript.
 */
test('structural quotes survive so the literal is valid javascript', function (): void {
    expect(CaptureScript::withConfig(['endpoint' => '/e']))
        ->toContain('{"endpoint":"/e"}')
        ->not->toContain('&quot;');
});

test('unicode in a config value is not escaped', function (): void {
    expect(CaptureScript::withConfig(['ignoredErrors' => ['naïve']]))->toContain('naïve');
});
