<?php

declare(strict_types=1);

use Ranetrace\Php\Support\SecretScrubber;

function scrubber(array $overrides = []): SecretScrubber
{
    return new SecretScrubber(testConfig($overrides));
}

test('it redacts values under sensitive keys', function (): void {
    $result = scrubber()->scrub([
        'password' => 'hunter2',
        'api_key' => 'sk_live_123',
        'token' => 'abc',
        'authorization' => 'Bearer xyz',
        'username' => 'alice',
    ]);

    expect($result['password'])->toBe('[REDACTED]')
        ->and($result['api_key'])->toBe('[REDACTED]')
        ->and($result['token'])->toBe('[REDACTED]')
        ->and($result['authorization'])->toBe('[REDACTED]')
        ->and($result['username'])->toBe('alice');
});

test('it matches sensitive keys case-insensitively and as substrings', function (): void {
    $result = scrubber()->scrub([
        'API_KEY' => 'x',
        'Stripe_Secret' => 'y',
        'csrf_token' => 'z',
        'safe' => 'keep',
    ]);

    expect($result['API_KEY'])->toBe('[REDACTED]')
        ->and($result['Stripe_Secret'])->toBe('[REDACTED]')
        ->and($result['csrf_token'])->toBe('[REDACTED]')
        ->and($result['safe'])->toBe('keep');
});

test('it redacts nested sensitive keys and the whole sensitive subtree', function (): void {
    $result = scrubber()->scrub([
        'user' => [
            'name' => 'bob',
            'credentials' => ['password' => 'p', 'pin' => '1234'],
        ],
        'authorization' => ['scheme' => 'Bearer', 'value' => 'tok'],
    ]);

    expect($result['user']['name'])->toBe('bob')
        ->and($result['user']['credentials'])->toBe('[REDACTED]')
        ->and($result['authorization'])->toBe('[REDACTED]');
});

test('it does not over-match unrelated keys', function (): void {
    $result = scrubber()->scrub([
        'author' => 'jane',
        'description' => 'a token of appreciation',
        'count' => 3,
    ]);

    // 'author' must not match 'authorization'; values (not keys) are never inspected.
    expect($result['author'])->toBe('jane')
        ->and($result['description'])->toBe('a token of appreciation')
        ->and($result['count'])->toBe(3);
});

test('it returns non-array input untouched', function (): void {
    expect(scrubber()->scrub('plain'))->toBe('plain')
        ->and(scrubber()->scrub(123))->toBe(123)
        ->and(scrubber()->scrub(null))->toBeNull();
});

test('it honors user-configured extra keys without dropping the built-ins', function (): void {
    $result = scrubber(['scrubbing' => ['extra_keys' => ['x_signature']]])->scrub([
        'x_signature' => 'deadbeef',
        'password' => 'hunter2',
        'keep' => 'ok',
    ]);

    expect($result['x_signature'])->toBe('[REDACTED]')
        ->and($result['password'])->toBe('[REDACTED]')
        ->and($result['keep'])->toBe('ok');
});

test('extra keys are matched case-insensitively', function (): void {
    $result = scrubber(['scrubbing' => ['extra_keys' => ['SeedValue']]])->scrub(['app_seedvalue' => 'x']);

    expect($result['app_seedvalue'])->toBe('[REDACTED]');
});

test('it preserves list/numeric-keyed arrays while scrubbing nested secrets', function (): void {
    $result = scrubber()->scrub([
        'headers' => [
            ['name' => 'Accept', 'value' => 'application/json'],
            ['name' => 'X-Api-Key', 'api_key' => 'secret-value'],
        ],
    ]);

    expect($result['headers'][0]['value'])->toBe('application/json')
        ->and($result['headers'][1]['api_key'])->toBe('[REDACTED]')
        ->and($result['headers'][1]['name'])->toBe('X-Api-Key');
});

test('scrubUrl redacts sensitive query params and preserves the rest', function (): void {
    expect(scrubber()->scrubUrl('https://example.com/reset?token=abc123&utm_source=google&page=2'))
        ->toBe('https://example.com/reset?token=[REDACTED]&utm_source=google&page=2');
});

test('scrubUrl redacts signed-url signatures', function (): void {
    expect(scrubber()->scrubUrl('https://example.com/invite?expires=1700000000&signature=deadbeef'))
        ->toBe('https://example.com/invite?expires=1700000000&signature=[REDACTED]');
});

test('scrubUrl preserves the fragment', function (): void {
    expect(scrubber()->scrubUrl('https://example.com/p?api_key=secret#section'))
        ->toBe('https://example.com/p?api_key=[REDACTED]#section');
});

test('scrubUrl leaves urls without sensitive params untouched', function (): void {
    expect(scrubber()->scrubUrl('https://example.com/list?page=2&sort=name'))
        ->toBe('https://example.com/list?page=2&sort=name')
        ->and(scrubber()->scrubUrl('https://example.com/plain'))
        ->toBe('https://example.com/plain')
        ->and(scrubber()->scrubUrl(null))->toBeNull()
        ->and(scrubber()->scrubUrl(''))->toBe('');
});

test('scrubDeep redacts secrets hiding in url-shaped values under innocent keys', function (): void {
    $result = scrubber()->scrubDeep([
        'endpoint' => 'https://api.test/v1/items?api_key=sk_live_9&page=2',
        'nested' => ['href' => 'http://example.test/a?token=abc'],
        'note' => 'not a url, token=abc stays',
        'token' => 'redacted by key',
    ]);

    expect($result['endpoint'])->toBe('https://api.test/v1/items?api_key=[REDACTED]&page=2')
        ->and($result['nested']['href'])->toBe('http://example.test/a?token=[REDACTED]')
        ->and($result['note'])->toBe('not a url, token=abc stays')
        ->and($result['token'])->toBe('[REDACTED]');
});

test('sensitiveRouteParameterValues returns the values of sensitively-named parameters', function (): void {
    expect(scrubber()->sensitiveRouteParameterValues([
        'token' => 'abc123',
        'reset_token' => 'def456',
        'hash' => 'deadbeef',
        'id' => '42',
        'slug' => 'my-post',
    ]))->toBe(['abc123', 'def456', 'deadbeef']);
});

test('sensitiveRouteParameterValues skips empty, non-scalar and duplicate values', function (): void {
    expect(scrubber()->sensitiveRouteParameterValues([
        'token' => '',
        'api_key' => null,
        'secret' => new stdClass,
        'password' => 'same',
        'password_confirmation_token' => 'same',
    ]))->toBe(['same'])
        ->and(scrubber()->sensitiveRouteParameterValues([]))->toBe([]);
});

test('sensitiveRouteParameterValues honours the binding field of a custom-key binding', function (): void {
    // `/invitations/{invitation:token}` names the parameter `invitation` and
    // records `token` as its binding field, and the field is the only place that
    // says the segment holds a secret.
    expect(scrubber()->sensitiveRouteParameterValues(
        ['invitation' => 'live-invite-abc', 'post' => 'my-post'],
        ['invitation' => 'token', 'post' => 'slug']
    ))->toBe(['live-invite-abc']);
});

test('isSensitiveRouteParameter matches on the name, the binding field, or neither', function (): void {
    expect(scrubber()->isSensitiveRouteParameter('token'))->toBeTrue()
        ->and(scrubber()->isSensitiveRouteParameter('hash'))->toBeTrue()
        ->and(scrubber()->isSensitiveRouteParameter('invitation', 'token'))->toBeTrue()
        ->and(scrubber()->isSensitiveRouteParameter('invitation'))->toBeFalse()
        ->and(scrubber()->isSensitiveRouteParameter('post', 'slug'))->toBeFalse()
        ->and(scrubber()->isSensitiveRouteParameter('post', ''))->toBeFalse();
});

test('the hash fragment applies to route parameters only, never to array keys', function (): void {
    $result = scrubber()->scrub([
        'user_agent_hash' => 'aaa',
        'session_id_hash' => 'bbb',
    ]);

    expect($result['user_agent_hash'])->toBe('aaa')
        ->and($result['session_id_hash'])->toBe('bbb');
});

test('scrubPathSegments redacts every segment equal to a sensitive value', function (): void {
    expect(scrubber()->scrubPathSegments('/reset/abc123/confirm/abc123', ['abc123']))
        ->toBe('/reset/[REDACTED]/confirm/[REDACTED]');
});

test('scrubPathSegments matches segments on their decoded form', function (): void {
    expect(scrubber()->scrubPathSegments('/invite/a%20b', ['a b']))
        ->toBe('/invite/[REDACTED]');
});

test('scrubPathSegments requires a whole-segment match', function (): void {
    expect(scrubber()->scrubPathSegments('/reset/abc123-suffix', ['abc123']))
        ->toBe('/reset/abc123-suffix');
});

test('scrubPathSegments leaves the path untouched without sensitive values', function (): void {
    expect(scrubber()->scrubPathSegments('/reset/abc123', []))->toBe('/reset/abc123')
        ->and(scrubber()->scrubPathSegments('/', ['abc123']))->toBe('/')
        ->and(scrubber()->scrubPathSegments('', ['abc123']))->toBe('');
});

test('scrubUrlPath redacts the path while preserving scheme, host, port, query and fragment', function (): void {
    expect(scrubber()->scrubUrlPath('https://example.com:8080/reset/abc123?page=2#top', ['abc123']))
        ->toBe('https://example.com:8080/reset/[REDACTED]?page=2#top');
});

test('scrubUrlPath composes with scrubUrl without re-encoding the query', function (): void {
    $url = 'https://example.com/reset/abc123?token=abc123&next=%2Fdashboard%3Fa%3D1';

    expect(scrubber()->scrubUrlPath(scrubber()->scrubUrl($url), ['abc123']))
        ->toBe('https://example.com/reset/[REDACTED]?token=[REDACTED]&next=%2Fdashboard%3Fa%3D1');
});

test('scrubUrlPath handles relative urls and urls without a path', function (): void {
    expect(scrubber()->scrubUrlPath('/reset/abc123?page=2', ['abc123']))
        ->toBe('/reset/[REDACTED]?page=2')
        ->and(scrubber()->scrubUrlPath('https://example.com', ['abc123']))
        ->toBe('https://example.com');
});

test('scrubUrlPath is a no-op when the host cannot name the sensitive segments', function (): void {
    expect(scrubber()->scrubUrlPath('https://example.com/reset/abc123', []))
        ->toBe('https://example.com/reset/abc123')
        ->and(scrubber()->scrubUrlPath('https://example.com/reset/abc123'))
        ->toBe('https://example.com/reset/abc123')
        ->and(scrubber()->scrubUrlPath('https://example.com/reset/abc123', null))
        ->toBe('https://example.com/reset/abc123')
        ->and(scrubber()->scrubUrlPath(null, ['abc123']))->toBeNull()
        ->and(scrubber()->scrubUrlPath('', ['abc123']))->toBe('');
});

test('scrubString redacts key=value secrets in free-form strings', function (): void {
    expect(scrubber()->scrubString('error with password=hunter2 in config'))
        ->toBe('error with password=[REDACTED] in config');
});

test('scrubString redacts json-style and arrow-style secrets', function (): void {
    expect(scrubber()->scrubString('"api_key":"sk_live_abc"'))->toBe('"api_key":"[REDACTED]"')
        ->and(scrubber()->scrubString("token => 'abc123'"))->toBe("token => '[REDACTED]'");
});

test('scrubString redacts query-string secrets while keeping the rest', function (): void {
    $scrubbed = scrubber()->scrubString('GET https://api.test/v1?api_key=secret&page=2');

    expect($scrubbed)->toContain('api_key=[REDACTED]')->and($scrubbed)->toContain('page=2');
});

test('scrubString leaves strings without sensitive keys untouched', function (): void {
    expect(scrubber()->scrubString('just a normal message, id=42'))->toBe('just a normal message, id=42')
        ->and(scrubber()->scrubString(''))->toBe('');
});

test('scrubString honours user-configured extra keys', function (): void {
    expect(scrubber(['scrubbing' => ['extra_keys' => ['seed']]])->scrubString('boot seed=abcdef done'))
        ->toBe('boot seed=[REDACTED] done');
});
