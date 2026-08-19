<?php

declare(strict_types=1);

use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;

function scrubber(array $overrides = []): SecretScrubber
{
    $config = testConfig($overrides);

    return new SecretScrubber($config, new InternalLogger($config));
}

function scrubberInternalLog(string $directory): string
{
    $files = glob($directory.'/internal-*.log') ?: [];

    return $files === [] ? '' : (string) file_get_contents($files[0]);
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

test('scrubDeep redacts a sensitive query param in a relative URL value', function (): void {
    // A signed download link recorded by the fetch/XHR breadcrumb hooks is
    // usually relative; only the absolute form used to be redacted.
    expect(scrubber()->scrubDeep(['url' => '/exports/42/download?expires=1735689600&signature=a1b2c3']))
        ->toBe(['url' => '/exports/42/download?expires=1735689600&signature=[REDACTED]']);
});

test('scrubDeep redacts relative URL shapes that carry no leading slash', function (string $value, string $expected): void {
    expect(scrubber()->scrubDeep(['u' => $value]))->toBe(['u' => $expected]);
})->with([
    'bare path' => ['api/user?token=SECRET', 'api/user?token=[REDACTED]'],
    'current directory' => ['./api/user?token=SECRET', './api/user?token=[REDACTED]'],
    'parent directory' => ['../api/user?token=SECRET', '../api/user?token=[REDACTED]'],
    'query only' => ['?token=SECRET', '?token=[REDACTED]'],
    'sub-delimiter in a sibling param' => ['/download?ids=1,2&signature=SECRET', '/download?ids=1,2&signature=[REDACTED]'],
    'unencoded @ in the path' => ['/users/@rutger/files?token=SECRET', '/users/@rutger/files?token=[REDACTED]'],
]);

test('scrubString redacts the whole value when PCRE gives up, and says so in the internal log', function (): void {
    // A PCRE limit failure used to return the input unscrubbed. Losing the
    // string beats leaking it, and the give-up must never be silent.
    //
    // The limit has to be pinned artificially low to reach this path at all:
    // the pattern is no longer super-linear, so no realistic input reaches the
    // real limit. The path still has to work, because a host can lower
    // `pcre.backtrack_limit` itself and PCRE gives up on bad UTF-8 too.
    $directory = tempDirectory();
    $scrubber = scrubber(['buffer_path' => $directory]);
    $value = str_repeat('token', 400);

    $limit = ini_get('pcre.backtrack_limit');

    try {
        ini_set('pcre.backtrack_limit', '10');

        $result = $scrubber->scrubString($value);
    } finally {
        ini_set('pcre.backtrack_limit', $limit === false ? '1000000' : $limit);
    }

    expect($result)->toBe('[REDACTED]')
        ->and($result)->not->toBe($value)
        ->and(scrubberInternalLog($directory))->toContain('WARNING')
        ->toContain('Backtrack limit');
});

test('scrubString stays linear on the long word runs that used to burn the backtrack limit', function (string $label, string $value, string $expected): void {
    // These are the shapes the pattern used to be quadratic on: a 50k run of
    // word characters, which cost one full re-scan per start position. PCRE
    // gave up and the whole value was redacted wholesale. The result is now the
    // precise redaction, which is only reachable if the engine never gave up.
    $started = microtime(true);

    $result = scrubber()->scrubString($value);

    expect($result)->toBe($expected)
        ->and(microtime(true) - $started)->toBeLessThan(1.0, $label);
})->with([
    'fragment leading the run' => [
        'fragment leading the run',
        'token'.str_repeat('a', 50_000).'=x',
        'token'.str_repeat('a', 50_000).'=[REDACTED]',
    ],
    'secret behind the run' => [
        'secret behind the run',
        str_repeat('a', 50_000).' password=hunter2',
        str_repeat('a', 50_000).' password=[REDACTED]',
    ],
    'run with no secret at all' => [
        'run with no secret at all',
        str_repeat('a', 50_000),
        str_repeat('a', 50_000),
    ],
]);

test('scrubDeep asks a callable which segments are secret in each url it finds', function (): void {
    // The seam a host with a router needs: free-form data holds URLs from other
    // requests than the current one, and only a per-URL lookup can say what
    // those hold. One shared list would redact the wrong URL's secret.
    $result = scrubber()->scrubDeep([
        'from' => 'https://app.test/reset-password/AAA',
        'to' => 'https://app.test/invitations/BBB',
        'unknown' => 'https://app.test/dashboard/CCC',
    ], fn (string $url): array => match (true) {
        str_contains($url, '/reset-password/') => ['AAA'],
        str_contains($url, '/invitations/') => ['BBB'],
        default => [],
    });

    expect($result)->toBe([
        'from' => 'https://app.test/reset-password/[REDACTED]',
        'to' => 'https://app.test/invitations/[REDACTED]',
        'unknown' => 'https://app.test/dashboard/CCC',
    ]);
});

test('scrubDeep passes the callable the value as recorded, before the query is redacted', function (): void {
    // A host resolves the URL by matching it against its routes, so it must see
    // what the browser recorded rather than a rewritten copy of it.
    $seen = [];

    scrubber()->scrubDeep(
        ['url' => '/reset-password/AAA?token=live'],
        function (string $url) use (&$seen): array {
            $seen[] = $url;

            return ['AAA'];
        }
    );

    expect($seen)->toBe(['/reset-password/AAA?token=live']);
});

test('scrubUrlPath resolves a callable against the url it was given', function (): void {
    expect(scrubber()->scrubUrlPath('/reset-password/AAA', fn (string $url): array => ['AAA']))
        ->toBe('/reset-password/[REDACTED]')
        ->and(scrubber()->scrubUrlPath('/reset-password/AAA', fn (string $url): ?array => null))
        ->toBe('/reset-password/AAA');
});

test('a resolver that throws leaves the path unscrubbed instead of breaking the capture', function (): void {
    // The callable is host code reaching for a router mid-capture. Monitoring
    // must never be the reason an application breaks.
    $directory = tempDirectory();

    $result = scrubber(['buffer_path' => $directory])->scrubDeep(
        ['url' => '/reset-password/AAA?token=live'],
        function (string $url): array {
            throw new RuntimeException('the router is not booted');
        }
    );

    expect($result)->toBe(['url' => '/reset-password/AAA?token=[REDACTED]'])
        ->and(scrubberInternalLog($directory))->toContain('the router is not booted');
});

test('scrubUrl redacts a query-shaped fragment', function (string $url, string $expected): void {
    // The OAuth implicit flow puts the grant in the fragment, where nothing
    // used to look for it.
    expect(scrubber()->scrubUrl($url))->toBe($expected);
})->with([
    'no query before it' => [
        'https://app.test/callback#access_token=abc&expires_in=3600',
        'https://app.test/callback#access_token=[REDACTED]&expires_in=3600',
    ],
    'query before it' => [
        'https://app.test/callback?state=xyz#access_token=abc&expires_in=3600',
        'https://app.test/callback?state=xyz#access_token=[REDACTED]&expires_in=3600',
    ],
    'sensitive in both halves' => [
        'https://app.test/callback?token=q#access_token=f',
        'https://app.test/callback?token=[REDACTED]#access_token=[REDACTED]',
    ],
    'relative reference' => [
        '/callback#access_token=abc',
        '/callback#access_token=[REDACTED]',
    ],
]);

test('scrubUrl returns a fragment that is not query-shaped byte-for-byte', function (string $url): void {
    expect(scrubber()->scrubUrl($url))->toBe($url);
})->with([
    'anchor after a query' => ['https://app.test/docs?page=2#section-2'],
    'plain anchor' => ['/path#anchor'],
    'hash route' => ['/app#/reset/abc123'],
    'absolute hash route' => ['https://app.test/app#/reset/abc123'],
    'empty fragment' => ['https://app.test/docs#'],
]);

test('scrubDeep redacts a declared sensitive value inside an SPA hash route', function (): void {
    // `/app#/reset/abc123` puts the token in a path-shaped fragment; segment
    // matching is exact, so this is safe on any fragment.
    expect(scrubber()->scrubDeep(['url' => '/app#/reset/abc123'], ['abc123']))
        ->toBe(['url' => '/app#/reset/[REDACTED]']);
});

test('scrubUrlPath redacts a sensitive segment in a path-shaped fragment', function (): void {
    expect(scrubber()->scrubUrlPath('https://app.test/app#/reset/abc123', ['abc123']))
        ->toBe('https://app.test/app#/reset/[REDACTED]')
        ->and(scrubber()->scrubUrlPath('/app#/reset/abc123', ['abc123']))
        ->toBe('/app#/reset/[REDACTED]')
        // A query between the path and the hash route must not move the window.
        ->and(scrubber()->scrubUrlPath('https://app.test/app?page=2#/reset/abc123', ['abc123']))
        ->toBe('https://app.test/app?page=2#/reset/[REDACTED]');
});

test('scrubUrlPath leaves a fragment without a sensitive segment byte-for-byte', function (): void {
    expect(scrubber()->scrubUrlPath('/docs#section-2', ['abc123']))->toBe('/docs#section-2');
});

test('scrubUrlPath redacts the path even when the query or fragment carries an absolute url', function (string $url, string $expected): void {
    // An unencoded `https://` in the query used to be mistaken for the URL's
    // own scheme, which moved the path window into the query and shipped the
    // live token untouched.
    expect(scrubber()->scrubUrlPath($url, ['TOKEN']))->toBe($expected)
        ->and(scrubber()->scrubDeep(['url' => $url], ['TOKEN']))->toBe(['url' => $expected]);
})->with([
    'no query' => ['/reset-password/TOKEN', '/reset-password/[REDACTED]'],
    'relative next' => ['/reset-password/TOKEN?next=/account', '/reset-password/[REDACTED]?next=/account'],
    'absolute next' => [
        '/reset-password/TOKEN?next=https://app.test/dashboard',
        '/reset-password/[REDACTED]?next=https://app.test/dashboard',
    ],
    'absolute return in the fragment' => [
        '/reset-password/TOKEN#ret=https://app.test/x',
        '/reset-password/[REDACTED]#ret=https://app.test/x',
    ],
    'absolute url with an absolute next' => [
        'https://app.test/reset-password/TOKEN?next=https://other/x',
        'https://app.test/reset-password/[REDACTED]?next=https://other/x',
    ],
    'protocol-relative' => ['//app.test/reset-password/TOKEN', '//app.test/reset-password/[REDACTED]'],
]);

test('scrubDeep leaves free-form values that merely contain a question mark untouched', function (string $value): void {
    // scrubUrl rewrites everything from the first `?` to the end, so admitting
    // a non-URL here would silently truncate it.
    expect(scrubber()->scrubDeep(['v' => $value]))->toBe(['v' => $value]);
})->with([
    'json payload' => ['{"callback":"/webhooks/return?token=abc","order_id":991,"amount":42.5}'],
    'ternary' => ['isset($token)?$token:null'],
    'regex' => ['/^(a|b)?token$/'],
    'prose' => ['Did the token=abc request fail?'],
    'markdown link' => ['[reset](/reset?token=abc)'],
    'windows path' => ['C:\Users\token'],
    'bare word' => ['token'],
]);
