<?php

declare(strict_types=1);

use Ranetrace\Php\Support\FingerprintGenerator;

function fingerprints(array $overrides = []): FingerprintGenerator
{
    return new FingerprintGenerator(testConfig($overrides));
}

test('it generates a consistent session id hash for the same inputs', function (): void {
    $generator = fingerprints();

    expect($generator->generateSessionIdHash('127.0.0.1', 'Test Browser', '2026-08-06'))
        ->toBe($generator->generateSessionIdHash('127.0.0.1', 'Test Browser', '2026-08-06'));
});

test('the session id hash rotates daily', function (): void {
    $generator = fingerprints();

    expect($generator->generateSessionIdHash('127.0.0.1', 'Test Browser', '2026-08-06'))
        ->not->toBe($generator->generateSessionIdHash('127.0.0.1', 'Test Browser', '2026-08-07'));
});

test('the session id hash defaults to today', function (): void {
    $generator = fingerprints();

    expect($generator->generateSessionIdHash('127.0.0.1', 'Test Browser'))
        ->toBe($generator->generateSessionIdHash('127.0.0.1', 'Test Browser', date('Y-m-d')));
});

test('it generates a different session id for different addresses', function (): void {
    $generator = fingerprints();

    expect($generator->generateSessionIdHash('127.0.0.1', 'Test Browser', '2026-08-06'))
        ->not->toBe($generator->generateSessionIdHash('192.168.1.1', 'Test Browser', '2026-08-06'));
});

test('it generates a different session id for different user agents', function (): void {
    $generator = fingerprints();

    expect($generator->generateSessionIdHash('127.0.0.1', 'Chrome Browser', '2026-08-06'))
        ->not->toBe($generator->generateSessionIdHash('127.0.0.1', 'Firefox Browser', '2026-08-06'));
});

test('only the first hundred characters of the user agent feed the session id', function (): void {
    $generator = fingerprints();
    $base = str_repeat('a', 100);

    expect($generator->generateSessionIdHash('127.0.0.1', $base.'-tail-one', '2026-08-06'))
        ->toBe($generator->generateSessionIdHash('127.0.0.1', $base.'-tail-two', '2026-08-06'));
});

test('a missing address or user agent still yields a hash', function (): void {
    expect(fingerprints()->generateSessionIdHash(null, null, '2026-08-06'))->toHaveLength(64);
});

test('it generates a user agent hash of sha256 length', function (): void {
    expect(fingerprints()->generateUserAgentHash('Test Browser'))->toHaveLength(64);
});

test('it returns an empty string for a missing user agent', function (): void {
    expect(fingerprints()->generateUserAgentHash(null))->toBe('')
        ->and(fingerprints()->generateUserAgentHash(''))->toBe('');
});

test('the user agent hash is consistent and distinguishes agents', function (): void {
    $generator = fingerprints();

    expect($generator->generateUserAgentHash('Test Browser'))->toBe($generator->generateUserAgentHash('Test Browser'))
        ->and($generator->generateUserAgentHash('Chrome'))->not->toBe($generator->generateUserAgentHash('Firefox'));
});

test('hashes change when the fingerprint salt changes', function (): void {
    $one = fingerprints(['fingerprint_salt' => 'salt-one']);
    $two = fingerprints(['fingerprint_salt' => 'salt-two']);

    expect($one->generateSessionIdHash('127.0.0.1', 'Test Browser', '2026-08-06'))
        ->not->toBe($two->generateSessionIdHash('127.0.0.1', 'Test Browser', '2026-08-06'))
        ->and($one->generateUserAgentHash('Test Browser'))
        ->not->toBe($two->generateUserAgentHash('Test Browser'));
});

test('it falls back to the api key when no dedicated salt is set', function (): void {
    $fallback = fingerprints()->generateUserAgentHash('Test Browser');
    $explicit = fingerprints(['fingerprint_salt' => 'test-api-key-12345'])->generateUserAgentHash('Test Browser');

    expect($fallback)->toBe($explicit)
        ->and($fallback)->toBe(hash_hmac('sha256', 'Test Browser', 'test-api-key-12345'));
});

test('hash is a plain hmac over the configured salt', function (): void {
    expect(fingerprints(['fingerprint_salt' => 'pepper'])->hash('raw-session-id'))
        ->toBe(hash_hmac('sha256', 'raw-session-id', 'pepper'));
});
