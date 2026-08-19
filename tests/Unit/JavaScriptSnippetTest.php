<?php

declare(strict_types=1);

use Ranetrace\Php\Config;
use Ranetrace\Php\JavaScript\Snippet;

/**
 * @param  array<string, mixed>  $overrides  Merged into `javascript_errors`.
 * @param  array<string, mixed>  $root  Merged into the root config.
 */
function snippet(array $overrides = [], array $root = []): Snippet
{
    return new Snippet(testConfig(array_replace([
        'javascript_errors' => array_replace(['enabled' => true], $overrides),
        'internal_logging' => ['enabled' => false],
    ], $root)));
}

/**
 * The runtime config object the rendered script carries.
 *
 * @return array<string, mixed>
 */
function renderedConfig(string $rendered): array
{
    expect($rendered)->toMatch('/const config = \{.*\};/');

    preg_match('/const config = (\{.*\});/', $rendered, $matches);

    return json_decode($matches[1], true, 512, JSON_THROW_ON_ERROR);
}

test('it renders nothing when javascript error tracking is off', function (array $overrides, array $root): void {
    expect(snippet($overrides, $root)->render(['endpoint' => '/ranetrace/js-errors']))->toBe('');
})->with([
    'feature disabled' => [['enabled' => false], []],
    'sdk disabled' => [['enabled' => true], ['enabled' => false]],
    'no api key' => [['enabled' => true], ['key' => '']],
]);

test('it refuses to render without an endpoint, because this sdk mounts no routes', function (array $options): void {
    snippet()->render($options);
})->with([
    'missing' => [[]],
    'empty' => [['endpoint' => '']],
    'not a string' => [['endpoint' => 123]],
])->throws(InvalidArgumentException::class, 'requires an `endpoint` option');

test('it wraps the capture script in a script tag with no nonce by default', function (): void {
    $rendered = snippet()->render(['endpoint' => '/ranetrace/js-errors']);

    expect($rendered)->toStartWith('<script>')
        ->and($rendered)->toEndWith('</script>')
        ->and($rendered)->not->toContain('nonce=');
});

test('it emits a nonce attribute when the host supplies one', function (): void {
    expect(snippet()->render(['endpoint' => '/e', 'nonce' => 'abc123']))
        ->toStartWith('<script nonce="abc123">');
});

test('it escapes the nonce so it cannot break out of the attribute', function (): void {
    expect(snippet()->render(['endpoint' => '/e', 'nonce' => 'a"><script>x']))
        ->toStartWith('<script nonce="a&quot;&gt;&lt;script&gt;x">');
});

test('it substitutes the config token completely', function (): void {
    $rendered = snippet()->render(['endpoint' => '/ranetrace/js-errors']);

    expect($rendered)->not->toContain('__RANETRACE_CONFIG__');
});

test('it injects the endpoint and the configured runtime values', function (): void {
    $rendered = snippet([
        'sample_rate' => 0.25,
        'capture_console_errors' => true,
        'max_breadcrumbs' => 5,
    ])->render(['endpoint' => 'https://app.test/ranetrace/js-errors']);

    expect(renderedConfig($rendered))->toBe([
        'endpoint' => 'https://app.test/ranetrace/js-errors',
        'enabled' => true,
        'sampleRate' => 0.25,
        'captureConsoleErrors' => true,
        'maxBreadcrumbs' => 5,
        'ignoredErrors' => Config::DEFAULT_IGNORED_JAVASCRIPT_ERRORS,
    ]);
});

test('it defaults to the shared ignored error list so the script and the relay filter alike', function (): void {
    $config = renderedConfig(snippet()->render(['endpoint' => '/e']));

    expect($config['ignoredErrors'])->toBe(Config::DEFAULT_IGNORED_JAVASCRIPT_ERRORS)
        ->and($config['ignoredErrors'])->toHaveCount(15)
        ->and($config['sampleRate'])->toBe(1.0)
        ->and($config['captureConsoleErrors'])->toBeFalse()
        ->and($config['maxBreadcrumbs'])->toBe(20);
});

test('a configured ignored error list replaces the defaults in the script', function (): void {
    $rendered = snippet(['ignored_errors' => ['Only this one']])->render(['endpoint' => '/e']);

    expect(renderedConfig($rendered)['ignoredErrors'])->toBe(['Only this one']);
});

/**
 * The shared script can send `X-CSRF-TOKEN`, because the Laravel SDK's relay sits
 * behind CSRF middleware. This SDK's relay does a same-origin check instead, so
 * the config it emits must leave `csrfToken` out and leave the header unsent.
 */
test('it carries no csrf token, because the relay checks the origin instead', function (): void {
    $rendered = snippet()->render(['endpoint' => '/e']);

    expect(renderedConfig($rendered))->not->toHaveKey('csrfToken');
});

test('a closing script tag inside a config value cannot terminate the tag early', function (): void {
    $rendered = snippet(['ignored_errors' => ['</script><script>alert(1)</script>']])->render(['endpoint' => '/e']);

    expect(mb_substr_count($rendered, '</script>'))->toBe(1)
        ->and(renderedConfig($rendered)['ignoredErrors'])->toBe(['</script><script>alert(1)</script>']);
});
