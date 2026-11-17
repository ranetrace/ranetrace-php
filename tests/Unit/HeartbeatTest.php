<?php

declare(strict_types=1);

use Composer\InstalledVersions;
use Ranetrace\Php\Http\Heartbeat;

it('carries the sdk in lower case and its version, and nothing else', function (string $sdk, string $expected): void {
    $body = new Heartbeat($sdk, 'v1.7.0')->body();

    expect($body)->toBe(['sdk' => $expected, 'sdk_version' => 'v1.7.0']);
})->with([
    'this package' => ['PHP', 'php'],
    'the laravel package' => ['Laravel', 'laravel'],
]);

it('names the sdk and the heartbeat in the user agent', function (string $sdk, string $expected): void {
    expect(new Heartbeat($sdk, 'v1.7.0')->userAgent())->toBe($expected);
})->with([
    'this package' => ['PHP', 'Ranetrace-PHP/Heartbeat/1.0'],
    'the laravel package' => ['Laravel', 'Ranetrace-Laravel/Heartbeat/1.0'],
]);

it('cuts a version over fifty characters to its first fifty', function (): void {
    $version = 'dev-'.str_repeat('a', 60);

    expect(new Heartbeat('PHP', $version)->body()['sdk_version'])->toBe('dev-'.str_repeat('a', 46));
});

it('counts the fifty in characters, not bytes', function (): void {
    $version = str_repeat('é', 51);

    expect(new Heartbeat('PHP', $version)->body()['sdk_version'])->toBe(str_repeat('é', 50));
});

it('sends a version of exactly fifty characters whole', function (): void {
    $version = str_repeat('1', 50);

    expect(new Heartbeat('PHP', $version)->body()['sdk_version'])->toBe($version);
});

it('sends unknown for a blank version, which the api would refuse', function (string $version): void {
    expect(new Heartbeat('PHP', $version)->body()['sdk_version'])->toBe('unknown');
})->with([
    'an empty version' => [''],
    'a version of whitespace' => ["  \t"],
]);

it('reads the version of an installed package from composer', function (): void {
    $heartbeat = Heartbeat::forPackage('PHP', 'ranetrace/ranetrace-php');

    expect($heartbeat->sdk)->toBe('PHP')
        ->and($heartbeat->version)->toBe(InstalledVersions::getPrettyVersion('ranetrace/ranetrace-php'))
        ->and($heartbeat->version)->not->toBe('unknown');
});

it('falls back to unknown for a package composer did not install', function (): void {
    $heartbeat = Heartbeat::forPackage('PHP', 'ranetrace/not-installed');

    expect($heartbeat->body())->toBe(['sdk' => 'php', 'sdk_version' => 'unknown']);
});
