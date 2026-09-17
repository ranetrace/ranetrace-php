<?php

declare(strict_types=1);

use Ranetrace\Php\Config;
use Ranetrace\Php\JavaScript\CaptureScript;
use Ranetrace\Php\Tests\TestCase;

uses(TestCase::class)->in('Unit', 'Feature', 'Contract');

/**
 * Environment variables a test set, so they can be removed again afterwards.
 * Config reads `$_ENV`, `$_SERVER` and `getenv()`, so all three are cleared.
 *
 * @var array<int, string>
 */
$GLOBALS['ranetrace_test_env_keys'] = [];

/**
 * Temporary directories a test created, removed after the test.
 *
 * @var array<int, string>
 */
$GLOBALS['ranetrace_test_temp_dirs'] = [];

uses()->afterEach(function (): void {
    foreach ($GLOBALS['ranetrace_test_env_keys'] as $name) {
        unset($_ENV[$name], $_SERVER[$name]);
        putenv($name);
    }

    $GLOBALS['ranetrace_test_env_keys'] = [];

    foreach ($GLOBALS['ranetrace_test_temp_dirs'] as $directory) {
        deleteTempDirectory($directory);
    }

    $GLOBALS['ranetrace_test_temp_dirs'] = [];
})->in('Unit', 'Feature', 'Contract');

/**
 * Set an environment variable for the duration of one test.
 */
function withEnv(string $name, ?string $value): void
{
    $GLOBALS['ranetrace_test_env_keys'][] = $name;

    if ($value === null) {
        unset($_ENV[$name], $_SERVER[$name]);
        putenv($name);

        return;
    }

    $_ENV[$name] = $value;
    putenv($name.'='.$value);
}

/**
 * A fresh, empty directory under the system temp dir, removed after the test.
 */
function tempDirectory(string $prefix = 'ranetrace-test-'): string
{
    $directory = sys_get_temp_dir().'/'.$prefix.bin2hex(random_bytes(6));

    mkdir($directory, 0775, true);

    $GLOBALS['ranetrace_test_temp_dirs'][] = $directory;

    return $directory;
}

function deleteTempDirectory(string $directory): void
{
    if (! is_dir($directory)) {
        return;
    }

    $entries = glob($directory.'/*') ?: [];

    foreach ($entries as $entry) {
        is_dir($entry) ? deleteTempDirectory($entry) : @unlink($entry);
    }

    @rmdir($directory);
}

/**
 * A Config with a usable API key, so `enabled()` gates open by default.
 *
 * @param  array<string, mixed>  $overrides
 */
function testConfig(array $overrides = []): Config
{
    return new Config(array_replace(['key' => 'test-api-key-12345'], $overrides));
}

/**
 * The runtime config object out of a rendered capture script.
 *
 * The script ships minified, so the variable the config is assigned to is a
 * one-letter name that a different esbuild version may spell differently, and no
 * test may key on it. The literal is located by the template around it instead: a
 * probe render gives the exact prefix and suffix the substitution sits between,
 * whatever the minifier called things.
 *
 * `$rendered` may be the bare script or a whole page with the script inside it.
 *
 * @return array<string, mixed>
 */
function capturedScriptConfig(string $rendered): array
{
    [$before, $after] = explode(
        '{"ranetraceProbe":true}',
        CaptureScript::withConfig(['ranetraceProbe' => true]),
        2,
    );

    $start = mb_strpos($rendered, $before);

    expect($start)->not->toBeFalse('the rendered output does not carry the capture script');

    $start += mb_strlen($before);
    $end = mb_strpos($rendered, $after, $start);

    expect($end)->not->toBeFalse('the capture script is truncated after the config literal');

    return json_decode(mb_substr($rendered, $start, $end - $start), true, 512, JSON_THROW_ON_ERROR);
}
