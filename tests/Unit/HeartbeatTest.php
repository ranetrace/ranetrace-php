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

it('takes any 2xx as accepted, whatever the body', function (array $result, bool $accepted): void {
    expect(Heartbeat::accepted($result))->toBe($accepted);
})->with([
    'a 200 with a body' => [['status' => 200, 'success' => true, 'data' => ['success' => true], 'headers' => ['retry-after' => ''], 'error' => null], true],
    'a 200 in the laravel client\'s shape' => [['status' => 200, 'success' => true, 'data' => ['success' => true], 'headers' => []], true],
    'a 204 without a body' => [['status' => 204, 'success' => false, 'data' => [], 'headers' => [], 'error' => 'Invalid response format'], true],
    'a 299' => [['status' => 299, 'data' => []], true],
    'a 199' => [['status' => 199, 'data' => []], false],
    'a 300' => [['status' => 300, 'data' => []], false],
    'a 401' => [['status' => 401, 'success' => false, 'data' => [], 'headers' => []], false],
    'no status reached' => [['status' => 0, 'success' => false, 'data' => [], 'headers' => ['retry-after' => null], 'error' => 'Connection refused'], false],
    'no status key' => [['data' => []], false],
    'a status that is not an integer' => [['status' => '200', 'data' => []], false],
]);

it('words the answer to a heartbeat for the release check', function (array $result, string $line): void {
    expect(Heartbeat::answerLine($result, 'https://api.example.test/v1'))->toBe($line);
})->with([
    'a 200' => [['status' => 200, 'success' => true, 'data' => ['success' => true], 'headers' => ['retry-after' => ''], 'error' => null], 'accepted'],
    'a 200 in the laravel client\'s shape' => [['status' => 200, 'success' => true, 'data' => ['success' => true], 'headers' => []], 'accepted'],
    'no status, with an error' => [
        ['status' => 0, 'success' => false, 'data' => [], 'headers' => ['retry-after' => null], 'error' => 'Connection refused'],
        'failed: could not reach https://api.example.test/v1 (Connection refused)',
    ],
    'no status and no error' => [
        ['status' => 0, 'success' => false, 'data' => [], 'headers' => []],
        'failed: could not reach https://api.example.test/v1 (unknown network error)',
    ],
    'a status that is not an integer' => [
        ['status' => '404', 'data' => []],
        'failed: could not reach https://api.example.test/v1 (unknown network error)',
    ],
    'a 404 with a message' => [
        ['status' => 404, 'success' => false, 'data' => ['success' => false, 'error' => ['message' => 'Not Found']], 'headers' => []],
        'refused: the API answered 404 (Not Found)',
    ],
    'a 500 without a message' => [
        ['status' => 500, 'success' => false, 'data' => [], 'headers' => ['retry-after' => ''], 'error' => null],
        'refused: the API answered 500 (no message)',
    ],
    'a 422 without a data key' => [
        ['status' => 422],
        'refused: the API answered 422 (no message)',
    ],
]);

it('falls back to unknown for a package composer did not install', function (): void {
    $heartbeat = Heartbeat::forPackage('PHP', 'ranetrace/not-installed');

    expect($heartbeat->body())->toBe(['sdk' => 'php', 'sdk_version' => 'unknown']);
});
