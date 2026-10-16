<?php

declare(strict_types=1);

use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;

function scrubber(array $overrides = []): SecretScrubber
{
    $config = testConfig($overrides);

    return new SecretScrubber($config, new InternalLogger($config));
}

/**
 * One source line scrubbed as a window of its own.
 */
function scrubSourceLine(string $line): string
{
    return scrubber()->scrubSource([$line])[0];
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

test('scrubString redacts a quoted value up to its closing quote, whatever it holds', function (string $line, string $expected): void {
    // A quoted value used to end at the first space, comma or semicolon and then
    // needed its closing quote right there, so any value holding one of those
    // was left whole. Source lines around a frame are full of exactly that.
    expect(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'array element' => ["'api_key' => 'sk_live_abc',", "'api_key' => '[REDACTED]',"],
    'assignment with a space' => ["\$password = 'two words';", "\$password = '[REDACTED]';"],
    'arrow with a comma inside' => ["'token' => \"a,b\",", "'token' => \"[REDACTED]\","],
    'json with a space' => ['{"password":"a b","user":"rutger"}', '{"password":"[REDACTED]","user":"rutger"}'],
    'escaped double quotes' => ['"password":"a \"b\" c"', '"password":"[REDACTED]"'],
    'escaped single quote' => ["'password' => 'it\\'s secret',", "'password' => '[REDACTED]',"],
    'the other quote inside' => ["'secret' => \"it's mine\",", "'secret' => \"[REDACTED]\","],
    'semicolon and paren inside' => ["\$secret = 'a;b)c}d&e';", "\$secret = '[REDACTED]';"],
    'named argument' => ["connect(token: 'x y', retries: 3);", "connect(token: '[REDACTED]', retries: 3);"],
    'comparison against a literal' => ["if (\$token === 'sk_live_x') {", "if (\$token === '[REDACTED]') {"],
    'loose comparison' => ["if (\$token != 'sk_live_x') {", "if (\$token != '[REDACTED]') {"],
]);

test('scrubString redacts the quoted value that follows a quoted sensitive key and a comma', function (string $line, string $expected): void {
    // define('NAME', 'value'), env('NAME', 'default') and a call or list whose
    // arguments are a key and then its value carry no separator at all.
    expect(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'define' => ["define('STRIPE_SECRET', 'sk_live_x');", "define('STRIPE_SECRET', '[REDACTED]');"],
    'env default' => ["'key' => env('STRIPE_SECRET', \"sk test\"),", "'key' => env('STRIPE_SECRET', \"[REDACTED]\"),"],
    'setter call' => ["\$config->set('services.api_key', 'abc def');", "\$config->set('services.api_key', '[REDACTED]');"],
    'list element' => ["['token', 'abc'],", "['token', '[REDACTED]'],"],
]);

test('scrubString never splits => into a separator and a redacted value', function (): void {
    // `=` used to match on its own when the value after `=>` failed, which ate
    // the `>` as the "value" and left the real one in place.
    expect(scrubber()->scrubString("'token' => \"a,b\","))->not->toContain('a,b')
        ->and(scrubber()->scrubString("'token' => \"a,b\","))->toContain('=>')
        ->and(scrubber()->scrubString("'password' => '',"))->toBe("'password' => '',")
        ->and(scrubber()->scrubString("'token' => ;"))->toBe("'token' => ;");
});

test('scrubString leaves class constants and static calls on a sensitive name alone', function (string $line): void {
    // `::` is not a key/value separator. Treating its first colon as one turned
    // every `PersonalAccessToken::` in a source line into a redaction.
    expect(scrubber()->scrubString($line))->toBe($line);
})->with([
    'class constant' => ['VerifyCsrfToken::class,'],
    'static call' => ['$found = PersonalAccessToken::findToken($plain);'],
    'quoted key alone' => ["throw new RuntimeException('Missing token in request');"],
    'quoted key before a variable' => ["Hash::check('password', \$user->password);"],
]);

test('scrubString redacts an unterminated quoted value to the end of its line and no further', function (): void {
    // A truncated message, or the first line of a multi-line string literal,
    // has no closing quote. Stopping at the line end keeps the next line of a
    // trace or message intact.
    expect(scrubber()->scrubString("\$secret = 'first line of"))->toBe("\$secret = '[REDACTED]")
        ->and(scrubber()->scrubString("password: 'abc\nnext line stays"))->toBe("password: '[REDACTED]\nnext line stays");
});

test('scrubString keeps the other pairs of a query string', function (): void {
    expect(scrubber()->scrubString('token=abc&x=1'))->toBe('token=[REDACTED]&x=1')
        ->and(scrubber()->scrubString('/cb?a=1&access_token=xyz&b=2'))->toBe('/cb?a=1&access_token=[REDACTED]&b=2');
});

test('scrubString redacts the credential of an authorization header, not its scheme', function (string $line, string $expected): void {
    // The scheme used to be taken for the value, so the credential after it
    // shipped as written.
    expect(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'bearer' => ['Authorization: Bearer abc123', 'Authorization: Bearer [REDACTED]'],
    'basic, lower case' => ['authorization: basic dXNlcjpwYXNz', 'authorization: basic [REDACTED]'],
    'scheme alone' => ['Authorization: Bearer', 'Authorization: [REDACTED]'],
]);

test('scrubString never keeps an unquoted value under a sensitive key', function (string $line, string $expected): void {
    // A message, a trace or a command line is not source: the shell or the
    // developer already put the secret there, so `$Up3r` or `(abc123)` is the
    // value itself, not code to keep.
    expect(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'console argument' => ['--password=$Up3r', '--password=[REDACTED]'],
    'log message' => ['Login failed with password=$Up3rS3cret for bob', 'Login failed with password=[REDACTED] for bob'],
    'curl header' => ['curl -H "Authorization: Bearer $TOKEN"', 'curl -H "Authorization: Bearer [REDACTED]"'],
    'environment prefix' => ['DB_PASSWORD=$ecr3t php artisan migrate', 'DB_PASSWORD=[REDACTED] php artisan migrate'],
    'parentheses' => ['token=(abc123)', 'token=[REDACTED]'],
    'square brackets' => ['api_key: [sk_live_abc]', 'api_key: [REDACTED]'],
    'braces' => ['secret={abc}', 'secret=[REDACTED]'],
    'nested json' => ['{"token":{"value":"abc"}}', '{"token":[REDACTED]}'],
    'brackets inside literals' => ['token=(a "b)" c) next', 'token=[REDACTED] next'],
    'an unclosed bracket' => ['token=(abc def', 'token=[REDACTED]'],
]);

test('scrubString never ships a literal inside a code-shaped value under a sensitive key', function (string $line, string $expected): void {
    // The value used to stop at its first quote, which left the literal, the
    // actual secret, behind the placeholder.
    expect(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'a static call' => ["'password' => Hash::make('x'),", "'password' => [REDACTED],"],
    'a call with arguments' => ["token=foo(bar, 'baz') rest", 'token=[REDACTED] rest'],
    'an env lookup' => ["secret: env('X', 'y')", 'secret: [REDACTED]'],
    'a chain after the call' => ["token=\$a->get('x')->value rest", 'token=[REDACTED] rest'],
    'a bracket inside a literal' => ["token=f(')', 'y') rest", 'token=[REDACTED] rest'],
    'an unclosed call' => ["token=f('x', 'y'", 'token=[REDACTED]'],
    'an unclosed call ends with its line' => ["token=f('x'\nnext 'line'", "token=[REDACTED]\nnext 'line'"],
]);

test('scrubString keeps the code and redacts the literals of a sensitive call, as source does', function (): void {
    $line = '#0 /app/Billing.php(12): App\Billing->setApiKey(\'sk_live_x\')';

    expect(scrubber()->scrubString($line))->toBe('#0 /app/Billing.php(12): App\Billing->setApiKey(\'[REDACTED]\')')
        ->and(scrubSourceLine($line))->toBe(scrubber()->scrubString($line));
});

test('the same line is read as code in source and redacted whole in a message', function (): void {
    $line = "'password' => Hash::make('x'),";

    expect(scrubSourceLine($line))->toBe("'password' => Hash::make('[REDACTED]'),")
        ->and(scrubber()->scrubString("'password' => \$input,"))->toBe("'password' => [REDACTED],")
        ->and(scrubSourceLine("'password' => \$input,"))->toBe("'password' => \$input,");
});

test('scrubSource keeps a code value after a sensitive key and redacts only its literals', function (string $line, string $expected): void {
    // An unquoted value used to run to the first quote or bracket, which cut
    // into the code, garbled it and left the literal after the cut, the real
    // secret, as written.
    expect(scrubSourceLine($line))->toBe($expected);
})->with([
    'hashing a literal' => ["'password' => Hash::make('x'),", "'password' => Hash::make('[REDACTED]'),"],
    'a function on a literal' => ["'password' => bcrypt('x'),", "'password' => bcrypt('[REDACTED]'),"],
    'a method chain on a literal' => ["\$secret = \$this->secrets->get('a b');", "\$secret = \$this->secrets->get('[REDACTED]');"],
    'validation rules' => ["'password' => ['required', 'confirmed'],", "'password' => ['[REDACTED]', '[REDACTED]'],"],
    'a namespaced call' => ["\$token = \\App\\Tokens::issue('t');", "\$token = \\App\\Tokens::issue('[REDACTED]');"],
    'new' => ["\$secret = new Secret('s', \$x);", "\$secret = new Secret('[REDACTED]', \$x);"],
    'a cast' => ["\$token = (string) 'abc';", "\$token = (string) '[REDACTED]';"],
    'a json object' => ['{"token": {"value": "abc"}, "user": "rutger"}', '{"token": {"[REDACTED]": "[REDACTED]"}, "user": "rutger"}'],
    'a silenced call' => ["\$secret = @file_get_contents('/run/secret');", "\$secret = @file_get_contents('[REDACTED]');"],
    'a concatenation' => ["\$token = \$prefix.'abc';", "\$token = \$prefix.'[REDACTED]';"],
    'a null-coalescing default' => ["'password' => \$input ?? 'fallback',", "'password' => \$input ?? '[REDACTED]',"],
    'an escaped quote inside a literal' => ["'password' => Hash::make('it\\'s, really'),", "'password' => Hash::make('[REDACTED]'),"],
    'an empty literal' => ["'password' => Hash::make(''),", "'password' => Hash::make(''),"],
    'a heredoc opener' => ["\$secret = <<<'EOT'", "\$secret = <<<'EOT'"],
]);

test('scrubSource reads a name spaced from its call as code and redacts the name', function (string $line, string $expected): void {
    // The value used to be a bare token up to the space, so the literals after
    // it shipped. A word spaced from a bracket is as likely prose in a comment
    // (`password: hunter2 (old)`) as a call, so the word goes and the rest is
    // read as code.
    expect(scrubSourceLine($line))->toBe($expected);
})->with([
    'a function' => ["'password' => bcrypt ('secret'),", "'password' => [REDACTED] ('[REDACTED]'),"],
    'a tab' => ["'password' => bcrypt\t('secret'),", "'password' => [REDACTED]\t('[REDACTED]'),"],
    'an env lookup keeps its name' => ["'password' => env ('DB_PASSWORD', 'default'),", "'password' => [REDACTED] ('DB_PASSWORD', '[REDACTED]'),"],
    'a static call' => ["'password' => Hash ::make('x'),", "'password' => [REDACTED] ::make('[REDACTED]'),"],
    'a method call' => ["'password' => app ->make('x'),", "'password' => [REDACTED] ->make('[REDACTED]'),"],
    'a word before a remark in a comment' => ['// password: hunter2 (rotated in May)', '// password: [REDACTED] (rotated in May)'],
    'a word before an arrow in a comment' => ['// token: abc -> def', '// token: [REDACTED] -> def'],
    'a constant spaced from a comparison stays a bare token' => ["'password' => SECRET_VALUE , 'name' => 'Bob'", "'password' => [REDACTED] , 'name' => 'Bob'"],
    'the next pair keeps its value' => ["'password' => f ('x'), 'name' => 'Bob'", "'password' => [REDACTED] ('[REDACTED]'), 'name' => 'Bob'"],
]);

test('scrubSource leaves a code value with no literal in it byte-for-byte', function (string $line): void {
    expect(scrubSourceLine($line))->toBe($line);
})->with([
    'a method call' => ["'remember_token' => \$user->getRememberToken(),"],
    'a static call on a number' => ['$token = Str::random(60);'],
    'a variable' => ["'token' => \$token,"],
    'a closure' => ["'token' => fn () => \$this->token,"],
    'a nullsafe chain' => ['$secret = $user?->secret;'],
    'a class constant' => ["'token' => self::DEFAULT_TOKEN,"],
]);

test('a code value ends at a comma or semicolon outside its brackets, so the next pair keeps its value', function (): void {
    expect(scrubSourceLine("'token' => \$x, 'name' => 'Bob'"))->toBe("'token' => \$x, 'name' => 'Bob'")
        ->and(scrubSourceLine("['token' => \$x], 'Bob'"))->toBe("['token' => \$x], 'Bob'")
        ->and(scrubSourceLine("\$token = \$x; \$name = 'Bob';"))->toBe("\$token = \$x; \$name = 'Bob';")
        ->and(scrubSourceLine("connect(token: \$t, name: 'Bob')"))->toBe("connect(token: \$t, name: 'Bob')")
        ->and(scrubSourceLine("'password' => Hash::make('x', ['rounds' => 12]), 'name' => 'Bob'"))
        ->toBe("'password' => Hash::make('[REDACTED]', ['[REDACTED]' => 12]), 'name' => 'Bob'");
});

test('a code value ends where a comment or a closing php tag starts', function (string $line, string $expected): void {
    // A quote inside a trailing comment is prose, not a literal of the value.
    expect(scrubSourceLine($line))->toBe($expected);
})->with([
    'a line comment' => ["'token' => \$x // the user's token", "'token' => \$x // the user's token"],
    'a hash comment' => ["'token' => \$x # the user's token", "'token' => \$x # the user's token"],
    'a block comment' => ["'token' => \$x /* it's */", "'token' => \$x /* it's */"],
    'a closing tag' => ["<?php \$token = \$x ?><p>'Bob'</p>", "<?php \$token = \$x ?><p>'Bob'</p>"],
    'an attribute is not a comment' => ["'token' => #[Sensitive] fn () => 'x',", "'token' => #[Sensitive] fn () => '[REDACTED]',"],
    'a url inside a literal' => ["'token' => \$base.'https://x.test/a',", "'token' => \$base.'[REDACTED]',"],
]);

test('scrubString redacts an unquoted value to the end of its line and leaves the next line of a trace alone', function (): void {
    expect(scrubber()->scrubString("token: \$x->get(\n#1 /app/Foo.php(12): bar('baz')"))
        ->toBe("token: [REDACTED]\n#1 /app/Foo.php(12): bar('baz')")
        ->and(scrubber()->scrubString("token=(abc\n#1 /app/Foo.php(12): bar('baz')"))
        ->toBe("token=[REDACTED]\n#1 /app/Foo.php(12): bar('baz')");
});

test('scrubString treats a quoted key that closes a subscript as a key', function (string $line, string $expected): void {
    // The `]` between the key and the separator used to hide the key, so an
    // assignment into a config array shipped its value as written.
    expect(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'single subscript' => ["\$config['password'] = 'hunter2';", "\$config['password'] = '[REDACTED]';"],
    'nested subscript' => ['$config["db"]["password"] = "hunter2";', '$config["db"]["password"] = "[REDACTED]";'],
    'environment' => ["\$_ENV['API_KEY'] = 'sk_live_x';", "\$_ENV['API_KEY'] = '[REDACTED]';"],
    'compared with a literal' => ["if (\$config['password'] === 'x') {", "if (\$config['password'] === '[REDACTED]') {"],
]);

test('a fallback after a sensitive key is its value', function (string $line, string $expected): void {
    // `??` and `?:` were not separators, so the literal a sensitive read falls
    // back to shipped as written.
    expect(scrubber()->scrubString($line))->toBe($expected)
        ->and(scrubSourceLine($line))->toBe($expected);
})->with([
    'a server header' => ["\$x = \$_SERVER['HTTP_AUTHORIZATION'] ?? 'Bearer abc';", "\$x = \$_SERVER['HTTP_AUTHORIZATION'] ?? '[REDACTED]';"],
    'a config subscript' => ["\$p = \$config['password'] ?? 'hunter2';", "\$p = \$config['password'] ?? '[REDACTED]';"],
    'a short ternary' => ["\$s = \$token ?: 'fallback';", "\$s = \$token ?: '[REDACTED]';"],
    'a null-coalescing assignment still wins over ??' => ["\$token ??= 'x';", "\$token ??= '[REDACTED]';"],
]);

test('a ternary on a sensitive variable and a fallback to code stay readable', function (string $line): void {
    expect(scrubber()->scrubString($line))->toBe($line)
        ->and(scrubSourceLine($line))->toBe($line);
})->with([
    'a full ternary' => ["\$label = \$token ? 'set' : 'missing';"],
    'a nullsafe chain' => ['$v = $token?->value;'],
]);

test('a fallback after a call read by a sensitive quoted key is its value', function (string $line, string $expected): void {
    expect(scrubber()->scrubString($line))->toBe($expected)
        ->and(scrubSourceLine($line))->toBe($expected);
})->with([
    'a request input' => ["\$p = \$request->input('password') ?? 'default';", "\$p = \$request->input('password') ?? '[REDACTED]';"],
    'a short ternary' => ["\$t = \$request->header(\"X-Api-Key\") ?: 'dev-key';", "\$t = \$request->header(\"X-Api-Key\") ?: '[REDACTED]';"],
    'blanks before the paren' => ["\$p = \$request->input( 'password' \t) ?? 'x';", "\$p = \$request->input( 'password' \t) ?? '[REDACTED]';"],
    'an env lookup keeps its name' => ["\$t = env('API_TOKEN') ?? 'x';", "\$t = env('API_TOKEN') ?? '[REDACTED]';"],
]);

test('a call read by a sensitive quoted key is not a key before anything but a fallback', function (string $line): void {
    // `strpos($x, 'token') !== false` is everywhere, and its `false` is not a
    // secret, so a comparison after the call does not make it a pair.
    expect(scrubber()->scrubString($line))->toBe($line)
        ->and(scrubSourceLine($line))->toBe($line);
})->with([
    'alone' => ["\$p = \$request->input('password');"],
    'a comparison' => ["if (strpos(\$header, 'token') !== false) {"],
    'an assignment after it' => ["\$p = input('password');"],
    'an unquoted argument' => ['$p = input(password) ?? $x;'],
    'blanks before the paren and a comparison' => ["if (strpos(\$x, 'token' ) !== false) {"],
]);

test('scrubSource keeps a fallback that is code', function (): void {
    expect(scrubSourceLine("\$p = \$config['password'] ?? \$input;"))->toBe("\$p = \$config['password'] ?? \$input;")
        ->and(scrubSourceLine('$s = $token ?: $this->issue();'))->toBe('$s = $token ?: $this->issue();');
});

test('scrubSource keeps a subscript key compared with code readable', function (): void {
    expect(scrubSourceLine("if (\$config['password'] === \$input) {"))->toBe("if (\$config['password'] === \$input) {")
        ->and(scrubSourceLine("\$value = \$config['password'];"))->toBe("\$value = \$config['password'];")
        ->and(scrubSourceLine("foo(\$config['token'], 'x');"))->toBe("foo(\$config['token'], 'x');")
        ->and(scrubSourceLine("\$config['password'] = Hash::make('x');"))->toBe("\$config['password'] = Hash::make('[REDACTED]');");
});

test('scrubString redacts the literals passed to a call whose name holds a sensitive fragment', function (string $line, string $expected): void {
    // The argument of a setter carries no key of its own, so the call's name is
    // the only thing that says what it holds.
    expect(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'static setter' => ["Stripe::setApiKey('sk_live_abc123');", "Stripe::setApiKey('[REDACTED]');"],
    'method setter' => ["\$client->setToken('tok_abc');", "\$client->setToken('[REDACTED]');"],
    'fluent call' => ["Http::withToken('abc')->get(\$url);", "Http::withToken('[REDACTED]')->get(\$url);"],
    'every argument' => ["\$client->setCredentials('user', 'pass');", "\$client->setCredentials('[REDACTED]', '[REDACTED]');"],
    'a function' => ["\$hash = password_hash('hunter2', PASSWORD_DEFAULT);", "\$hash = password_hash('[REDACTED]', PASSWORD_DEFAULT);"],
    'nested arguments' => ["\$c->setSecret(trim('a'), ['k' => 'v']);", "\$c->setSecret(trim('[REDACTED]'), ['[REDACTED]' => '[REDACTED]']);"],
    'the rest of the line is untouched' => ["\$c->setToken('a'); \$name = 'Bob';", "\$c->setToken('[REDACTED]'); \$name = 'Bob';"],
    'a frame in a text trace' => ['#0 /app/Billing.php(12): App\Billing->setApiKey(\'sk_live_x\')', '#0 /app/Billing.php(12): App\Billing->setApiKey(\'[REDACTED]\')'],
]);

test('scrubString leaves a sensitive call with no literal byte-for-byte', function (string $line): void {
    expect(scrubber()->scrubString($line))->toBe($line);
})->with([
    'getter' => ['return $user->getRememberToken();'],
    'static lookup' => ['$found = PersonalAccessToken::findToken($token);'],
    'no arguments' => ['PersonalAccessToken::findToken();'],
    'a helper' => ['<input type="hidden" value="{{ csrf_token() }}">'],
]);

test('a call whose name ends in Exception or Error is not a sensitive call', function (string $line): void {
    // Its argument is a message, which already travels in the error's message
    // field, and a throw line is the line a source window highlights.
    expect(scrubber()->scrubString($line))->toBe($line)
        ->and(scrubSourceLine($line))->toBe($line);
})->with([
    'an exception' => ["throw new TokenMismatchException('CSRF token mismatch.');"],
    'an error' => ["throw new InvalidTokenError('The token has expired.');"],
    'lower case' => ["throw new tokenexception('expired');"],
    'a static constructor on it' => ["throw TokenException::expired('x');"],
    'a setter named for an error' => ["\$this->setTokenError('Expired, please retry.');"],
]);

test('a call that only contains Exception or Error in its name is still a sensitive call', function (string $line, string $expected): void {
    expect(scrubber()->scrubString($line))->toBe($expected)
        ->and(scrubSourceLine($line))->toBe($expected);
})->with([
    'a setter' => ["Stripe::setApiKey('x');", "Stripe::setApiKey('[REDACTED]');"],
    'a credentials setter' => ["\$c->setCredentials('u', 'p');", "\$c->setCredentials('[REDACTED]', '[REDACTED]');"],
    'a plural suffix' => ["\$c->setTokenErrors('x');", "\$c->setTokenErrors('[REDACTED]');"],
    'exception in the middle' => ["new TokenExceptionFactory('x');", "new TokenExceptionFactory('[REDACTED]');"],
]);

test('a sensitive key still governs a value that constructs an exception', function (): void {
    expect(scrubSourceLine("'token' => new TokenException('x'),"))->toBe("'token' => new TokenException('[REDACTED]'),")
        ->and(scrubber()->scrubString("'token' => new TokenException('x'),"))->toBe("'token' => [REDACTED],")
        ->and(scrubSourceLine("throw new TokenException('password=hunter2');"))->toBe("throw new TokenException('password=[REDACTED]');");
});

test('scrubSource keeps an exception spread over several lines and its heredoc readable', function (array $lines): void {
    expect(scrubber()->scrubSource($lines))->toBe($lines);
})->with([
    'arguments on lines of their own' => [['throw new TokenMismatchException(', "    'CSRF token mismatch.',", ');']],
    'a heredoc message' => [['throw new TokenException(<<<EOT', 'The token expired.', 'EOT);']],
]);

test('scrubSource keeps the name read by env, getenv, config or a superglobal and redacts the rest', function (string $line, string $expected): void {
    // The first argument of such a lookup names where a secret lives; the
    // secret is the default after it, if there is one.
    expect(scrubSourceLine($line))->toBe($expected);
})->with([
    'env with a default' => ["'password' => env('DB_PASSWORD', 'x'),", "'password' => env('DB_PASSWORD', '[REDACTED]'),"],
    'env alone' => ["'password' => env('DB_PASSWORD'),", "'password' => env('DB_PASSWORD'),"],
    'env in double quotes and spaced' => ["'password' => env( \"DB_PASSWORD\" , 'x' ),", "'password' => env( \"DB_PASSWORD\" , '[REDACTED]' ),"],
    'env in upper case' => ["'password' => ENV('DB_PASSWORD'),", "'password' => ENV('DB_PASSWORD'),"],
    'a global env' => ["'password' => \\env('DB_PASSWORD', 'x'),", "'password' => \\env('DB_PASSWORD', '[REDACTED]'),"],
    'getenv with a fallback' => ["\$secret = getenv('APP_SECRET') ?: 'x';", "\$secret = getenv('APP_SECRET') ?: '[REDACTED]';"],
    'config' => ["\$token = config('services.api.token');", "\$token = config('services.api.token');"],
    'config with a default' => ["\$token = config('services.api.token', 'x');", "\$token = config('services.api.token', '[REDACTED]');"],
    'the env subscript' => ["'password' => \$_ENV['DB_PASSWORD'] ?? 'x',", "'password' => \$_ENV['DB_PASSWORD'] ?? '[REDACTED]',"],
    'the server subscript' => ["'password' => \$_SERVER['DB_PASSWORD'],", "'password' => \$_SERVER['DB_PASSWORD'],"],
    'a sensitive call on env' => ["\$client->setToken(env('API_TOKEN'));", "\$client->setToken(env('API_TOKEN'));"],
    'a credential call on env' => ["new PDO(env('DB_DSN'), env('DB_USER'), 'x');", "new PDO(env('DB_DSN'), env('DB_USER'), '[REDACTED]');"],
    'a default that is itself an env' => ["'password' => env('A', env('B', 'x')),", "'password' => env('A', env('B', '[REDACTED]')),"],
    'a default that is a call with a literal' => ["'password' => env('A', trim('x')),", "'password' => env('A', trim('[REDACTED]')),"],
]);

test('scrubSource keeps only a plain literal that is the first argument of a global lookup', function (string $line, string $expected): void {
    expect(scrubSourceLine($line))->toBe($expected);
})->with([
    'config given an array' => ["'password' => config(['a.secret' => 'sk_live_x']),", "'password' => config(['[REDACTED]' => '[REDACTED]']),"],
    'config given an array on its own line' => ["config(['services.stripe.secret' => 'sk_live_x']);", "config(['services.stripe.secret' => '[REDACTED]']);"],
    'a name built by concatenation' => ["'password' => env('DB_' . 'PASSWORD'),", "'password' => env('[REDACTED]' . '[REDACTED]'),"],
    'a variable name' => ["'password' => env(\$name, 'x'),", "'password' => env(\$name, '[REDACTED]'),"],
    'a method named config' => ["'password' => \$this->config('x'),", "'password' => \$this->config('[REDACTED]'),"],
    'a static method named env' => ["'password' => Settings::env('x'),", "'password' => Settings::env('[REDACTED]'),"],
    'a namespaced function' => ["'password' => App\\env('x'),", "'password' => App\\env('[REDACTED]'),"],
    'a longer name' => ["'password' => myenv('x'),", "'password' => myenv('[REDACTED]'),"],
    'a variable call' => ["'password' => \$env('x'),", "'password' => \$env('[REDACTED]'),"],
    'a lower case superglobal is another variable' => ["'password' => \$_env['x'],", "'password' => \$_env['[REDACTED]'],"],
    'another array' => ["'password' => \$secrets['x'],", "'password' => \$secrets['[REDACTED]'],"],
    'putenv is not a lookup' => ["'password' => putenv('DB_PASSWORD=hunter2'),", "'password' => putenv('[REDACTED]'),"],
    'a name that is not alone in its slot' => ["'password' => env('A' ?: 'b'),", "'password' => env('[REDACTED]' ?: '[REDACTED]'),"],
    'a superglobal subscript built by concatenation' => ["'password' => \$_ENV['A' . 'B'],", "'password' => \$_ENV['[REDACTED]' . '[REDACTED]'],"],
]);

test('scrubSource redacts an env name on the line after its call', function (): void {
    expect(scrubber()->scrubSource(["'password' => env(", "    'DB_PASSWORD',", "    'x'", '),']))
        ->toBe(["'password' => env(", "    '[REDACTED]',", "    '[REDACTED]'", '),']);
});

test('scrubString redacts a constructor call under a sensitive key whole', function (string $line, string $expected): void {
    // An exception-named call is not an anchor of its own, so the prose value
    // has to take the call along with `new`.
    expect(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'an exception' => ["'token' => new TokenException('x'), 'name' => 'Bob'", "'token' => [REDACTED], 'name' => 'Bob'"],
    'a namespaced class' => ["token=new \\App\\Secret('x') rest", 'token=[REDACTED] rest'],
    'new as a word' => ['password=new value', 'password=[REDACTED] value'],
]);

test('scrubString keeps an env name inside a sensitive call and redacts an env lookup under a key whole', function (): void {
    expect(scrubber()->scrubString("\$client->setToken(env('API_TOKEN', 'x'));"))->toBe("\$client->setToken(env('API_TOKEN', '[REDACTED]'));")
        ->and(scrubber()->scrubString("'password' => env('DB_PASSWORD'),"))->toBe("'password' => [REDACTED],");
});

test('scrubString redacts the literals passed to a known credential-taking call', function (string $line, string $expected): void {
    // Positional arguments carry no marker, so a call whose name says nothing
    // about a credential is caught only when it is on the curated list.
    expect(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'new PDO' => ["\$pdo = new PDO(\$dsn, 'root', 'hunter2');", "\$pdo = new PDO(\$dsn, '[REDACTED]', '[REDACTED]');"],
    'new \PDO' => ["\$pdo = new \\PDO('mysql:host=db', 'root', 'hunter2');", "\$pdo = new \\PDO('[REDACTED]', '[REDACTED]', '[REDACTED]');"],
    'new\PDO with no space' => ["\$pdo = new\\PDO(\$dsn, 'root', 'pw');", "\$pdo = new\\PDO(\$dsn, '[REDACTED]', '[REDACTED]');"],
    'new mysqli' => ["\$db = new mysqli('db', 'root', 'hunter2', 'app');", "\$db = new mysqli('[REDACTED]', '[REDACTED]', '[REDACTED]', '[REDACTED]');"],
    'pdo constructor in a text trace' => [
        "#0 /app/Db.php(12): PDO->__construct('mysql:host=db', 'root', Object(SensitiveParameterValue))",
        "#0 /app/Db.php(12): PDO->__construct('[REDACTED]', '[REDACTED]', Object(SensitiveParameterValue))",
    ],
    'mysqli constructor in a text trace' => [
        "#0 /app/Db.php(12): mysqli->__construct('db', 'root', Object(SensitiveParameterValue))",
        "#0 /app/Db.php(12): mysqli->__construct('[REDACTED]', '[REDACTED]', Object(SensitiveParameterValue))",
    ],
    'mysqli_connect' => ["mysqli_connect('db', 'root', 'hunter2');", "mysqli_connect('[REDACTED]', '[REDACTED]', '[REDACTED]');"],
    'mysqli_real_connect' => ["mysqli_real_connect(\$db, 'h', 'root', 'pw');", "mysqli_real_connect(\$db, '[REDACTED]', '[REDACTED]', '[REDACTED]');"],
    'real_connect' => ["\$db->real_connect('h', 'root', 'pw');", "\$db->real_connect('[REDACTED]', '[REDACTED]', '[REDACTED]');"],
    'ldap_bind' => ["ldap_bind(\$ldap, 'cn=admin', 'pw');", "ldap_bind(\$ldap, '[REDACTED]', '[REDACTED]');"],
    'ldap_sasl_bind' => ["ldap_sasl_bind(\$ldap, null, 'pw');", "ldap_sasl_bind(\$ldap, null, '[REDACTED]');"],
    'ftp_login' => ["ftp_login(\$ftp, 'user', 'pw');", "ftp_login(\$ftp, '[REDACTED]', '[REDACTED]');"],
    'ssh2_auth_password' => ["ssh2_auth_password(\$ssh, 'user', 'pw');", "ssh2_auth_password(\$ssh, '[REDACTED]', '[REDACTED]');"],
    'imap_open' => ["imap_open('{imap.test:993}', 'user', 'pw');", "imap_open('[REDACTED]', '[REDACTED]', '[REDACTED]');"],
    'withBasicAuth' => ["Http::withBasicAuth('user', 'pass')->get(\$url);", "Http::withBasicAuth('[REDACTED]', '[REDACTED]')->get(\$url);"],
    'withDigestAuth' => ["Http::withDigestAuth('user', 'pass');", "Http::withDigestAuth('[REDACTED]', '[REDACTED]');"],
    'upper case and a space before the paren' => ["MYSQLI_CONNECT ('db', 'root', 'pw');", "MYSQLI_CONNECT ('[REDACTED]', '[REDACTED]', '[REDACTED]');"],
    'nested parentheses' => [
        "new PDO(sprintf('mysql:host=%s', \$h), 'root', 'pw');",
        "new PDO(sprintf('[REDACTED]', \$h), '[REDACTED]', '[REDACTED]');",
    ],
    'the rest of the line is untouched' => ["new PDO(\$dsn, 'root', 'pw'); \$name = 'Bob';", "new PDO(\$dsn, '[REDACTED]', '[REDACTED]'); \$name = 'Bob';"],
]);

test('scrubString leaves calls that only look like a credential-taking call readable', function (string $line): void {
    // The curated names match as whole words only, and `auth` is not one of
    // them: Laravel's `auth('api')` helper is everywhere.
    expect(scrubber()->scrubString($line))->toBe($line);
})->with([
    'a longer name around a listed one' => ["my_mysqli_connect_wrapper('db', 'root');"],
    'a listed name as a prefix' => ["mysqli_connect_errno('x');"],
    'a class whose name starts with a listed one' => ["throw new PDOException('Connection refused');"],
    'new glued to the class name' => ["newPDO('x');"],
    'the auth helper' => ["\$user = auth('api')->user();"],
    'a key that starts with auth' => ["'author' => 'Jane',"],
    'a credential call with no literal' => ['$pdo = new PDO($dsn, $user, $password);'],
    'a constructor of a subclass' => ["new MyPDO('dsn', 'root');"],
    'a method of the class that is not the constructor' => ["PDO->prepare('SELECT 1')"],
    'withBasicAuth with no literal' => ['Http::withBasicAuth($user, $pass);'],
]);

test('scrubSource reads parent::__construct as a credential call in a PDO or mysqli subclass', function (array $lines, array $expected): void {
    // A subclass passes the credentials on to the constructor PHP masks only
    // in a trace, so the call's name says nothing, but its class does.
    expect(scrubber()->scrubSource($lines))->toBe($expected);
})->with([
    'one line' => [
        ['class Db extends PDO', '{', "    public function __construct() { parent::__construct(\$dsn, 'root', 'hunter2'); }", '}'],
        ['class Db extends PDO', '{', "    public function __construct() { parent::__construct(\$dsn, '[REDACTED]', '[REDACTED]'); }", '}'],
    ],
    'over several lines' => [
        ['final class Db extends \\PDO {', '    parent::__construct(', "        'mysql:host=db',", "        'root',", "        'hunter2',", '    );', "    \$name = 'Bob';"],
        ['final class Db extends \\PDO {', '    parent::__construct(', "        '[REDACTED]',", "        '[REDACTED]',", "        '[REDACTED]',", '    );', "    \$name = 'Bob';"],
    ],
    'mysqli in lower case, spaced' => [
        ['class Db extends mysqli', "parent :: __construct ('db', 'root', 'pw');"],
        ['class Db extends mysqli', "parent :: __construct ('[REDACTED]', '[REDACTED]', '[REDACTED]');"],
    ],
    'the class name on the line after extends' => [
        ['class Db extends', '    \\PDO', '{', "    parent::__construct(\$dsn, 'root', 'pw');"],
        ['class Db extends', '    \\PDO', '{', "    parent::__construct(\$dsn, '[REDACTED]', '[REDACTED]');"],
    ],
    'a blank line between extends and the class name' => [
        ['class Db extends', '', 'mysqli {', "parent::__construct('db', 'root', 'pw');"],
        ['class Db extends', '', 'mysqli {', "parent::__construct('[REDACTED]', '[REDACTED]', '[REDACTED]');"],
    ],
    'the extends line far above the call' => [
        ['class Db extends PDO', ...array_fill(0, 40, '    // filler'), "parent::__construct(\$dsn, 'root', 'pw');"],
        ['class Db extends PDO', ...array_fill(0, 40, '    // filler'), "parent::__construct(\$dsn, '[REDACTED]', '[REDACTED]');"],
    ],
]);

test('scrubSource leaves parent::__construct readable outside a PDO or mysqli subclass', function (array $lines): void {
    expect(scrubber()->scrubSource($lines))->toBe($lines);
})->with([
    'an exception subclass' => [['class Expired extends RuntimeException', "parent::__construct('Your session has expired.');"]],
    'a PDO exception subclass' => [['class DbFailed extends PDOException', "parent::__construct('Connection refused.');"]],
    'a class whose name starts with PDO' => [['class Db extends PDOWrapper', "parent::__construct('root', 'pw');"]],
    'a namespaced PDO' => [['class Db extends App\\PDO', "parent::__construct('root', 'pw');"]],
    'a PDO exception on the line after extends' => [['class Failed extends', '    PDOException', "parent::__construct('Connection refused.');"]],
    'no extends line at all' => [["parent::__construct(\$dsn, 'root', 'pw');"]],
]);

test('a PDO subclass in one window does not change how the next window is read', function (): void {
    $scrubber = scrubber();
    $scrubber->scrubSource(['class Db extends PDO', "parent::__construct('root', 'pw');"]);

    expect($scrubber->scrubSource(["parent::__construct('Expired.');"]))->toBe(["parent::__construct('Expired.');"])
        ->and($scrubber->scrubString("parent::__construct('Expired.') extends PDO"))->toBe("parent::__construct('Expired.') extends PDO");
});

test('scrubSource redacts the literals passed to a known credential-taking call', function (array $lines, array $expected): void {
    expect(scrubber()->scrubSource($lines))->toBe($expected);
})->with([
    'new PDO on one line' => [["\$pdo = new PDO(\$dsn, 'root', 'hunter2');"], ["\$pdo = new PDO(\$dsn, '[REDACTED]', '[REDACTED]');"]],
    'new PDO over several lines' => [
        ['$pdo = new PDO(', "    'mysql:host=db;dbname=app',", "    'root',", "    'hunter2',", ');', "\$name = 'Bob';"],
        ['$pdo = new PDO(', "    '[REDACTED]',", "    '[REDACTED]',", "    '[REDACTED]',", ');', "\$name = 'Bob';"],
    ],
    'mysqli_connect' => [["\$db = mysqli_connect('db', 'root', 'hunter2');"], ["\$db = mysqli_connect('[REDACTED]', '[REDACTED]', '[REDACTED]');"]],
    'withBasicAuth' => [
        ["\$response = Http::withBasicAuth('user', 'pass')->get(\$url);"],
        ["\$response = Http::withBasicAuth('[REDACTED]', '[REDACTED]')->get(\$url);"],
    ],
    'a heredoc passed to one' => [
        ["ftp_login(<<<'EOT'", 'hunter2', 'EOT);'],
        ["ftp_login(<<<'EOT'", '[REDACTED]', 'EOT);'],
    ],
    'a credential call with no literal' => [
        ['$pdo = new PDO(', '    $dsn,', '    $user,', ');'],
        ['$pdo = new PDO(', '    $dsn,', '    $user,', ');'],
    ],
]);

test('scrubString redacts a literal concatenated onto a quoted secret', function (string $line, string $expected): void {
    // Only the first literal used to be redacted; the one joined onto it with
    // `.` shipped as written.
    expect(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'two literals' => ["'password' => 'abc' . 'def',", "'password' => '[REDACTED]' . '[REDACTED]',"],
    'with code between' => ["\$token = 'abc'.\$x.'def'; \$name = 'Bob';", "\$token = '[REDACTED]'.\$x.'[REDACTED]'; \$name = 'Bob';"],
    'after a quoted key and a comma' => ["define('API_SECRET', 'abc' . 'def');", "define('API_SECRET', '[REDACTED]' . '[REDACTED]');"],
    'a variable after it is code' => ["\$token = 'abc' . \$suffix;", "\$token = '[REDACTED]' . \$suffix;"],
    'a full stop in prose is not a concatenation' => ["token: 'abc'. Then 'x' happened", "token: '[REDACTED]'. Then 'x' happened"],
]);

test('a validation message key keeps its message', function (string $line): void {
    // A dotted key whose last segment is a validation rule names a message,
    // and a message is what a reader needs from a FormRequest.
    expect(scrubber()->scrubString($line))->toBe($line)
        ->and(scrubSourceLine($line))->toBe($line);
})->with([
    'required' => ["'password.required' => 'Vul je wachtwoord in',"],
    'min' => ["'password.min' => 'At least :min characters.',"],
    'upper case' => ["'PASSWORD.CONFIRMED' => 'The passwords differ.',"],
    'a nested field' => ["'user.api_token.required_with' => 'Required with the account.',"],
    'a wildcard' => ["'tokens.*.required' => 'Every token needs a value.',"],
    'current_password' => ["'password.current_password' => 'That is not your password.',"],
    'in double quotes' => ['"password.uncompromised" => "That password has leaked.",'],
    'in json' => ['{"password.required":"Vul je wachtwoord in"}'],
]);

test('a dotted key is a message key only when its last segment is a rule', function (string $line, string $expected): void {
    expect(scrubber()->scrubString($line))->toBe($expected)
        ->and(scrubSourceLine($line))->toBe($expected);
})->with([
    'a config key' => ["'stripe.secret' => 'x',", "'stripe.secret' => '[REDACTED]',"],
    'no dot' => ["'password' => 'x',", "'password' => '[REDACTED]',"],
    'a nested config key' => ["'services.stripe.secret' => 'x',", "'services.stripe.secret' => '[REDACTED]',"],
    'a segment that is not a rule' => ["'password.live' => 'x',", "'password.live' => '[REDACTED]',"],
    'the rule first' => ["'required.password' => 'x',", "'required.password' => '[REDACTED]',"],
    'a rule name inside a longer segment' => ["'password.not_required' => 'x',", "'password.not_required' => '[REDACTED]',"],
    'a subscript holding a message key' => ["\$config['password.min'] = 8;", "\$config['password.min'] = 8;"],
    'a rule joined by a dash' => ["'password-required' => 'x',", "'password-required' => '[REDACTED]',"],
    'an unquoted key' => ['token.min=abc', 'token.min=[REDACTED]'],
    'an unquoted key before an arrow' => ["password.required => 'x'", "password.required => '[REDACTED]'"],
]);

test('a validation message key at the end of a line does not carry onto the next', function (): void {
    expect(scrubber()->scrubSource(["'password.required' =>", "    'Vul je wachtwoord in',"]))
        ->toBe(["'password.required' =>", "    'Vul je wachtwoord in',"])
        ->and(scrubber()->scrubSource(["'password.required' => <<<EOT", 'Vul je wachtwoord in', 'EOT,']))
        ->toBe(["'password.required' => <<<EOT", 'Vul je wachtwoord in', 'EOT,'])
        ->and(scrubSourceLine("'password' => Password::min(8)->letters(),"))->toBe("'password' => Password::min(8)->letters(),");
});

test('scrubString redacts the value after a quoted label that holds a sensitive word', function (): void {
    // A translation key such as 'Enter your password' cannot be told from a
    // key, so its value is redacted. That costs a readable string, never a
    // secret.
    expect(scrubber()->scrubString("'Enter your password' => 'Voer je wachtwoord in',"))
        ->toBe("'Enter your password' => '[REDACTED]',");
});

test('scrubString still redacts a bare token whole, whatever it spells', function (string $line, string $expected): void {
    // true, null, numbers and constants stay bare tokens: they are redacted as
    // before, which hides nothing a reader needs.
    expect(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'a word' => ['password=hunter2', 'password=[REDACTED]'],
    'null' => ["'token' => null,", "'token' => [REDACTED],"],
    'a number' => ['$token = 42;', '$token = [REDACTED];'],
    'a constant' => ["'secret' => SECRET_VALUE,", "'secret' => [REDACTED],"],
    'a bcrypt hash' => ['password=$2y$10$abcdefghijklmnopqrstuv', 'password=[REDACTED]'],
    'punctuation first' => ['password=!hunter2 next', 'password=[REDACTED] next'],
    'inside brackets' => ['[token=abc]', '[token=[REDACTED]]'],
]);

test('scrubString keeps multibyte text whole and valid', function (): void {
    $quoted = scrubber()->scrubString("\$password = 'wachtwoord met ü en 日本';");
    $bare = scrubber()->scrubString('token=日本語 rest ünchanged');

    expect($quoted)->toBe("\$password = '[REDACTED]';")
        ->and($bare)->toBe('token=[REDACTED] rest ünchanged')
        ->and(mb_check_encoding($bare, 'UTF-8'))->toBeTrue()
        ->and(scrubber()->scrubString('Gebruiker « ü » heeft geen 日本 rechten'))->toBe('Gebruiker « ü » heeft geen 日本 rechten');
});

test('scrubString keeps multibyte keys and values whole under a UTF-8 locale', function (): void {
    // The pattern has no `u` flag, and outside the C locale PHP builds PCRE's
    // character tables from the locale, where `\s` and `\w` can match single
    // bytes of a multibyte character (0xA0 is a space in en_US.UTF-8, and the
    // second byte of `à`). A value cut on such a byte ends up invalid UTF-8.
    $previous = setlocale(LC_CTYPE, '0');

    if (setlocale(LC_CTYPE, 'en_US.UTF-8', 'C.UTF-8') === false) {
        $this->markTestSkipped('no UTF-8 locale available');
    }

    try {
        $results = [
            scrubber()->scrubString("'pässwörd_token' => 'geheimnis ü'"),
            scrubber()->scrubString("\$token = 'ü€𝄞';"),
            scrubber()->scrubString('token=àà rest'),
            scrubber()->scrubString('password: 𝄞à'),
            scrubber()->scrubString("'password' => ['à'], 'naam' => 'Zoë à'"),
        ];
    } finally {
        setlocale(LC_CTYPE, $previous === false ? 'C' : $previous);
    }

    expect($results)->toBe([
        "'pässwörd_token' => '[REDACTED]'",
        "\$token = '[REDACTED]';",
        'token=[REDACTED] rest',
        'password: [REDACTED]',
        "'password' => [REDACTED], 'naam' => 'Zoë à'",
    ]);

    foreach ($results as $result) {
        expect(mb_check_encoding($result, 'UTF-8'))->toBeTrue();
    }
});

test('scrubSource reads the start of the next line as the value of a key that ends a line', function (array $lines, array $expected): void {
    // Each line used to be scrubbed on its own, so a value formatted onto the
    // line after its key shipped as written.
    expect(scrubber()->scrubSource($lines))->toBe($expected);
})->with([
    'array element' => [["'password' =>", "    'hunter2',"], ["'password' =>", "    '[REDACTED]',"]],
    'assignment' => [['$token =', "    'abc';"], ['$token =', "    '[REDACTED]';"]],
    'code value' => [["'password' =>", "    Hash::make('x'),"], ["'password' =>", "    Hash::make('[REDACTED]'),"]],
    'sensitive call' => [
        ['Stripe::setApiKey(', "    'sk_live_x'", ');'],
        ['Stripe::setApiKey(', "    '[REDACTED]'", ');'],
    ],
    'sensitive call, several arguments' => [
        ['$client->setCredentials(', "    'user', 'pass'", ');'],
        ['$client->setCredentials(', "    '[REDACTED]', '[REDACTED]'", ');'],
    ],
    'the rest of the next line is scrubbed as usual' => [
        ["'password' =>", "    'x', 'token' => 'y', 'name' => 'Bob'"],
        ["'password' =>", "    '[REDACTED]', 'token' => '[REDACTED]', 'name' => 'Bob'"],
    ],
]);

test('scrubSource reads the line after a fallback that ends a line as its value', function (array $lines, array $expected): void {
    expect(scrubber()->scrubSource($lines))->toBe($expected);
})->with([
    'a subscript' => [["\$p = \$config['password'] ??", "    'hunter2';"], ["\$p = \$config['password'] ??", "    '[REDACTED]';"]],
    'a short ternary' => [['$s = $token ?:', "    'fallback';"], ['$s = $token ?:', "    '[REDACTED]';"]],
    'a call key with blanks before the paren' => [["\$p = input( 'password' ) ??", "    'default';"], ["\$p = input( 'password' ) ??", "    '[REDACTED]';"]],
    'a call read by a sensitive key' => [["\$p = \$request->input('password') ??", "    'default';"], ["\$p = \$request->input('password') ??", "    '[REDACTED]';"]],
    'a heredoc' => [["\$p = \$config['password'] ?? <<<EOT", 'hunter2', 'EOT;'], ["\$p = \$config['password'] ?? <<<EOT", '[REDACTED]', 'EOT;']],
]);

test('scrubSource reads a fallback that starts the line after a sensitive read as its value', function (array $lines, array $expected): void {
    expect(scrubber()->scrubSource($lines))->toBe($expected);
})->with([
    'a call key' => [["\$p = \$request->input('password')", "    ?? 'x';"], ["\$p = \$request->input('password')", "    ?? '[REDACTED]';"]],
    'a subscript' => [["\$p = \$config['password']", "    ?: 'x';"], ["\$p = \$config['password']", "    ?: '[REDACTED]';"]],
    'a variable' => [['$p = $token', "    ?? Hash::make('x');"], ['$p = $token', "    ?? Hash::make('[REDACTED]');"]],
    'a call key with blanks before its paren' => [["\$p = input( 'password' )", "\t?? 'x';"], ["\$p = input( 'password' )", "\t?? '[REDACTED]';"]],
    'a null-coalescing assignment' => [["\$config['password']", "    ??= 'x';"], ["\$config['password']", "    ??= '[REDACTED]';"]],
    'a fallback whose bracket stays open' => [
        ['$p = $token', '    ?? Hash::make(', "        'x'", '    );', "\$name = 'Bob';"],
        ['$p = $token', '    ?? Hash::make(', "        '[REDACTED]'", '    );', "\$name = 'Bob';"],
    ],
    'only the fallback' => [["\$p = \$config['password']", "    ?? 'x'; \$name = 'Bob';"], ["\$p = \$config['password']", "    ?? '[REDACTED]'; \$name = 'Bob';"]],
]);

test('scrubSource does not carry a sensitive read onto a next line that is not a fallback', function (array $lines): void {
    expect(scrubber()->scrubSource($lines))->toBe($lines);
})->with([
    'a fallback that is code' => [["\$p = \$config['password']", '    ?? $default;']],
    'a method call' => [["\$p = \$request->input('password')", "    ->trim('x');"]],
    'a semicolon' => [['$p = $token', "    ; \$name = 'Bob';"]],
    'a comparison' => [['if ($token', "    === 'x') {"]],
    'a blank line between' => [["\$p = \$config['password']", '', "    ?? 'x';"]],
    'a key that is not sensitive' => [["\$p = \$config['name']", "    ?? 'x';"]],
    'a call key before a full ternary' => [["\$p = input('password')", "    ? 'a' : 'b';"]],
]);

test('scrubSource does not carry a full ternary or a call key before a comparison', function (array $lines): void {
    expect(scrubber()->scrubSource($lines))->toBe($lines);
})->with([
    'a ternary' => [['$label = $token ?', "    'set' : 'missing';"]],
    'a call key before a comparison' => [["if (strpos(\$x, 'token') ===", "    'abc') {"]],
]);

test('scrubSource carries an open bracket of a sensitive value onto the lines after it until it closes', function (array $lines, array $expected): void {
    // Only the line after the opening bracket used to be read as the value, so
    // a call or a code value spread over more lines shipped its later literals.
    expect(scrubber()->scrubSource($lines))->toBe($expected);
})->with([
    'sensitive call over several lines' => [
        ['$client->setCredentials(', "    'user',", "    'pass'", ');', "\$name = 'Bob';"],
        ['$client->setCredentials(', "    '[REDACTED]',", "    '[REDACTED]'", ');', "\$name = 'Bob';"],
    ],
    'code value over several lines' => [
        ["'password' => Hash::make(", "    'x'", '),', "'name' => 'Bob',"],
        ["'password' => Hash::make(", "    '[REDACTED]'", '),', "'name' => 'Bob',"],
    ],
    'the rest of the closing line is scrubbed as usual' => [
        ['Stripe::setApiKey(', "    'a'); \$token = 'b'; \$name = 'Bob';"],
        ['Stripe::setApiKey(', "    '[REDACTED]'); \$token = '[REDACTED]'; \$name = 'Bob';"],
    ],
    'nested brackets and a blank line' => [
        ['$c->setSecret([', "    'a' => ['b'],", '', "    'c',", ']);', "\$x = 'y';"],
        ['$c->setSecret([', "    '[REDACTED]' => ['[REDACTED]'],", '', "    '[REDACTED]',", ']);', "\$x = 'y';"],
    ],
    'a literal open inside the call' => [
        ['$c->setToken(', "    'a", "b', 'c'", ');', "\$x = 'y';"],
        ['$c->setToken(', "    '[REDACTED]", "[REDACTED]', '[REDACTED]'", ');', "\$x = 'y';"],
    ],
    'a bracket that never closes costs only literals' => [
        ["'token' => \$this->issue(function () {", "    return \$x . 'y';", '    $z = 1;'],
        ["'token' => \$this->issue(function () {", "    return \$x . '[REDACTED]';", '    $z = 1;'],
    ],
]);

test('scrubSource carries an open bracket of a sensitive value past a comment', function (array $lines, array $expected): void {
    // A comment used to end the value, so the arguments after it shipped.
    expect(scrubber()->scrubSource($lines))->toBe($expected);
})->with([
    'a line comment on a line of its own' => [
        ['$client->setCredentials(', '    // filler', "    'user',", "    'pass',", ');', "\$name = 'Bob';"],
        ['$client->setCredentials(', '    // filler', "    '[REDACTED]',", "    '[REDACTED]',", ');', "\$name = 'Bob';"],
    ],
    'a hash comment' => [
        ['$client->setCredentials(', "    # the user's", "    'user',", ');'],
        ['$client->setCredentials(', "    # the user's", "    '[REDACTED]',", ');'],
    ],
    'a block comment on a line of its own' => [
        ['$client->setCredentials(', '    /* filler */', "    'user',", ');'],
        ['$client->setCredentials(', '    /* filler */', "    '[REDACTED]',", ');'],
    ],
    'a trailing comment after an argument' => [
        ['$client->setCredentials(', "    'user', // it's the user", "    'pass'", ');'],
        ['$client->setCredentials(', "    '[REDACTED]', // it's the user", "    '[REDACTED]'", ');'],
    ],
    'an open code bracket' => [
        ["'password' => Hash::make(", '    // the plain text', "    'x'", '),', "'name' => 'Bob',"],
        ["'password' => Hash::make(", '    // the plain text', "    '[REDACTED]'", '),', "'name' => 'Bob',"],
    ],
    'a comment that holds a key of its own' => [
        ['$c->setCredentials(', '    // token: abc', "    'pass'", ');'],
        ['$c->setCredentials(', '    // token: [REDACTED]', "    '[REDACTED]'", ');'],
    ],
    'a block comment that runs onto the next line' => [
        ['$c->setToken(', '    /* first', "    second */ 'x'", ');', "\$name = 'Bob';"],
        ['$c->setToken(', '    /* first', "    second */ '[REDACTED]'", ');', "\$name = 'Bob';"],
    ],
    'a block comment with an apostrophe before its end' => [
        ['$c->setToken(', '    /* first', "    it's */ 'x'", ');', "\$name = 'Bob';"],
        ['$c->setToken(', '    /* first', "    it's */ '[REDACTED]'", ');', "\$name = 'Bob';"],
    ],
    'a block comment of several lines' => [
        ['$c->setCredentials(', "    /* the user's", "    name, and don't", '       forget the', "    password: hunter2 */ 'u',", "    'p'", ');', "\$name = 'Bob';"],
        ['$c->setCredentials(', "    /* the user's", "    name, and don't", '       forget the', "    password: [REDACTED] */ '[REDACTED]',", "    '[REDACTED]'", ');', "\$name = 'Bob';"],
    ],
    'a block comment reopened after one closes' => [
        ['$c->setToken(', '    /* a', "    b */ 'u', /* c", '', "    d */ 'p'", ');'],
        ['$c->setToken(', '    /* a', "    b */ '[REDACTED]', /* c", '', "    d */ '[REDACTED]'", ');'],
    ],
    'a block comment that never closes in the window' => [
        ["'password' => Hash::make(", "    /* it's", "    'x'"],
        ["'password' => Hash::make(", "    /* it's", "    'x'"],
    ],
    'a closing php tag still ends it' => [
        ['$c->setCredentials(', "    'u' ?>", "<p>'Bob'</p>"],
        ['$c->setCredentials(', "    '[REDACTED]' ?>", "<p>'Bob'</p>"],
    ],
]);

test('scrubSource reads past a block comment inside a sensitive call and scrubs the comment', function (string $line, string $expected): void {
    expect(scrubSourceLine($line))->toBe($expected)
        ->and(scrubber()->scrubString($line))->toBe($expected);
})->with([
    'between arguments' => ["\$c->setCredentials('u' /* pw */, 'p');", "\$c->setCredentials('[REDACTED]' /* pw */, '[REDACTED]');"],
    'a secret inside it' => ["\$c->setCredentials(/* password=hunter2 */ 'p');", "\$c->setCredentials(/* password=[REDACTED] */ '[REDACTED]');"],
    'a quote inside it' => ["\$c->setToken(/* it's */ 'p');", "\$c->setToken(/* it's */ '[REDACTED]');"],
]);

test('a code value outside a call still ends at a trailing comment', function (): void {
    expect(scrubber()->scrubSource(["'password' => \$x, // it's the input", "    'Bob',"]))->toBe(["'password' => \$x, // it's the input", "    'Bob',"])
        ->and(scrubber()->scrubSource(["'password' => \$x // it's", "'Bob'"]))->toBe(["'password' => \$x // it's", "'Bob'"]);
});

test('scrubSource stops carrying once the bracket of a sensitive value closes', function (): void {
    $lines = ["'password' => Hash::make(\$a,", '    $b),', "'name' => 'Bob',", "    'Alice',"];

    expect(scrubber()->scrubSource($lines))->toBe($lines);
});

test('scrubSource carries a value over only after an assignment or a call, and only one line', function (array $lines): void {
    // `case 'token':` followed by `return $x;` is code to read, and so is the
    // literal a sensitive value is compared with on the next line.
    expect(scrubber()->scrubSource($lines))->toBe($lines);
})->with([
    'a case label' => [["case 'token':", "    return 'abc';"]],
    'a comparison' => [['if ($token ===', "    'abc') {"]],
    'a key with no separator' => [["'password'", "    'abc'"]],
    'two lines ahead' => [["'password' =>", '', "    'abc',"]],
    'a key that is not sensitive' => [["'name' =>", "    'Bob',"]],
    'a call that is not sensitive' => [['Hash::check(', "    'abc'", ');']],
]);

test('scrubSource returns one line per line given, in order', function (): void {
    $lines = ['<?php', '', '$token = Str::random(60);', 'password=hunter2', '    return $x;'];

    expect(scrubber()->scrubSource($lines))->toBe(['<?php', '', '$token = Str::random(60);', 'password=[REDACTED]', '    return $x;'])
        ->and(scrubber()->scrubSource([]))->toBe([])
        ->and(scrubber()->scrubSource([3 => 'token=a', 7 => 'x']))->toBe(['token=[REDACTED]', 'x']);
});

test('scrubSource redacts the body of a private key and keeps its markers and code shape', function (array $lines, array $expected): void {
    expect(scrubber()->scrubSource($lines))->toBe($expected);
})->with([
    'a block in a string' => [
        [
            '$key = "-----BEGIN RSA PRIVATE KEY-----\n"',
            '    . "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n"',
            '    . "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\n"',
            '    . "-----END RSA PRIVATE KEY-----";',
        ],
        [
            '$key = "-----BEGIN RSA PRIVATE KEY-----\n"',
            '    . "[REDACTED]\n"',
            '    . "[REDACTED]\n"',
            '    . "-----END RSA PRIVATE KEY-----";',
        ],
    ],
    'a block in a heredoc, with a short last line' => [
        ['-----BEGIN PRIVATE KEY-----', 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj', 'AbC1=', '-----END PRIVATE KEY-----'],
        ['-----BEGIN PRIVATE KEY-----', '[REDACTED]', '[REDACTED]', '-----END PRIVATE KEY-----'],
    ],
    'the window starts inside the block' => [
        ['    xyz1AbC/+', '    AbC1=', '    -----END OPENSSH PRIVATE KEY-----', "    \$name = 'Bob';"],
        ['    [REDACTED]', '    [REDACTED]', '    -----END OPENSSH PRIVATE KEY-----', "    \$name = 'Bob';"],
    ],
    'the window ends inside the block' => [
        ["\$name = 'Bob';", '-----BEGIN EC PRIVATE KEY-----', 'short1A'],
        ["\$name = 'Bob';", '-----BEGIN EC PRIVATE KEY-----', '[REDACTED]'],
    ],
    'the window sits inside the body' => [
        ['MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj', "'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\\n' ."],
        ['[REDACTED]', "'[REDACTED]\\n' ."],
    ],
    'a single line' => [
        ['$key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----";'],
        ['$key = "-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----";'],
    ],
    'a pgp block' => [
        ['-----BEGIN PGP PRIVATE KEY BLOCK-----', 'Version: 1', '', 'lQOYBF', '-----END PGP PRIVATE KEY BLOCK-----'],
        ['-----BEGIN PGP PRIVATE KEY BLOCK-----', '[REDACTED]', '', '[REDACTED]', '-----END PGP PRIVATE KEY BLOCK-----'],
    ],
]);

test('scrubSource keeps a certificate marker and a long path readable', function (): void {
    // A certificate is public, though a base64 line of its body can still be
    // taken for a key body: that costs the line, never a secret.
    $lines = [
        '-----BEGIN CERTIFICATE-----',
        "'/var/www/html/storage/app/public/uploads/images/avatars',",
        'SomeVeryLongIdentifierWithoutAnyDigitsInItAtAllReally',
        '-----END CERTIFICATE-----',
    ];

    expect(scrubber()->scrubSource($lines))->toBe($lines);
});

test('scrubSource redacts the body of a heredoc or nowdoc assigned to a sensitive key', function (array $lines, array $expected): void {
    expect(scrubber()->scrubSource($lines))->toBe($expected);
})->with([
    'nowdoc' => [
        ["\$secret = <<<'EOT'", '    abc def', '    EOT;', "\$name = 'Bob';"],
        ["\$secret = <<<'EOT'", '    [REDACTED]', '    EOT;', "\$name = 'Bob';"],
    ],
    'heredoc in an array' => [
        ["'token' => <<<EOT", 'abc', '', 'EOT,'],
        ["'token' => <<<EOT", '[REDACTED]', '', 'EOT,'],
    ],
    'a sensitive call' => [
        ['$c->setToken(<<<"TXT"', 'abc', 'TXT);'],
        ['$c->setToken(<<<"TXT"', '[REDACTED]', 'TXT);'],
    ],
    'no closing marker in the window' => [
        ['$password = <<<EOT', 'EOTX is not the marker', 'still body'],
        ['$password = <<<EOT', '[REDACTED]', '[REDACTED]'],
    ],
    'not a sensitive key' => [
        ['$body = <<<EOT', 'Hello', 'EOT;'],
        ['$body = <<<EOT', 'Hello', 'EOT;'],
    ],
]);

test('scrubSource goes on redacting a sensitive string literal that runs onto the next lines', function (array $lines, array $expected): void {
    // The first line used to lose its literal to the end of the line and the
    // rest of the literal, on the lines after it, shipped as written.
    expect(scrubber()->scrubSource($lines))->toBe($expected);
})->with([
    'quoted value' => [
        ["\$secret = 'line one", 'line two', "  line three';  \$name = 'Bob';", "\$x = 'y';"],
        ["\$secret = '[REDACTED]", '[REDACTED]', "  [REDACTED]';  \$name = 'Bob';", "\$x = 'y';"],
    ],
    'inside a code value' => [
        ["'password' => Hash::make(\"abc", 'def"),', "'name' => 'Bob',"],
        ["'password' => Hash::make(\"[REDACTED]", '[REDACTED]"),', "'name' => 'Bob',"],
    ],
    'an escaped quote on the next line' => [
        ["\$token = 'a", "it\\'s', 'Bob'"],
        ["\$token = '[REDACTED]", "[REDACTED]', 'Bob'"],
    ],
    'an empty line inside it' => [
        ["\$token = 'a", '', "b';"],
        ["\$token = '[REDACTED]", '', "[REDACTED]';"],
    ],
]);

test('scrubSource leaves the lines after an open literal alone when no sensitive key holds it', function (): void {
    $lines = ["\$name = 'line one", 'line two', "';"];

    expect(scrubber()->scrubSource($lines))->toBe($lines);
});

test('scrubSource redacts the whole window when PCRE gives up, and says so in the internal log', function (): void {
    $directory = tempDirectory();
    $scrubber = scrubber(['buffer_path' => $directory]);
    $limit = ini_get('pcre.backtrack_limit');

    try {
        ini_set('pcre.backtrack_limit', '10');

        $result = $scrubber->scrubSource(['$name = 1;', str_repeat('token', 400), '$x = 2;']);
    } finally {
        ini_set('pcre.backtrack_limit', $limit === false ? '1000000' : $limit);
    }

    expect($result)->toBe(['[REDACTED]', '[REDACTED]', '[REDACTED]'])
        ->and(scrubberInternalLog($directory))->toContain('source window failed');
});

test('scrubSource stays linear on long windows', function (string $label, array $lines, array $expected): void {
    $started = microtime(true);

    $result = scrubber()->scrubSource($lines);

    expect($result)->toBe($expected)
        ->and(microtime(true) - $started)->toBeLessThan(1.0, $label);
})->with([
    'eleven long base64 lines' => [
        'eleven long base64 lines',
        array_fill(0, 11, str_repeat('Ab1+', 12_500)),
        array_fill(0, 11, '[REDACTED]'),
    ],
    'a begin with no end' => [
        'a begin with no end',
        ['-----BEGIN PRIVATE KEY-----', ...array_fill(0, 10, str_repeat('Ab1 ', 12_500))],
        ['-----BEGIN PRIVATE KEY-----', ...array_fill(0, 10, '[REDACTED] ')],
    ],
    'many markers on one line' => [
        'many markers on one line',
        [str_repeat('-----BEGIN '.str_repeat('A', 39), 1_000)],
        [str_repeat('-----BEGIN '.str_repeat('A', 39), 1_000)],
    ],
    'a key and a long run of spaces at the end of every line' => [
        'a key and a long run of spaces at the end of every line',
        array_fill(0, 11, "'token' =>".str_repeat(' ', 50_000).'x'),
        array_fill(0, 11, "'token' =>".str_repeat(' ', 50_000).'[REDACTED]'),
    ],
    'a code value of many literals' => [
        'a code value of many literals',
        ["'password' => f(".str_repeat("('a', ", 50_000)],
        ["'password' => f(".str_repeat("('[REDACTED]', ", 50_000)],
    ],
    'an unterminated quote inside a code value' => [
        'an unterminated quote inside a code value',
        ["'password' => Hash::make('".str_repeat('a, ', 20_000)],
        ["'password' => Hash::make('[REDACTED]"],
    ],
    'an open literal' => [
        'an open literal',
        ["\$secret = '".str_repeat('a ', 25_000), ...array_fill(0, 10, str_repeat('b ', 25_000))],
        ["\$secret = '[REDACTED]", ...array_fill(0, 10, '[REDACTED]')],
    ],
    'keys that never end a line' => [
        'keys that never end a line',
        array_fill(0, 11, str_repeat("'token' => \$x ", 5_000)),
        array_fill(0, 11, "'token' => ".str_repeat("\$x '[REDACTED]' => ", 4_999).'$x '),
    ],
    'a sensitive call left open over the window' => [
        'a sensitive call left open over the window',
        ['setToken(', ...array_fill(0, 10, str_repeat("('a', ", 10_000))],
        ['setToken(', ...array_fill(0, 10, str_repeat("('[REDACTED]', ", 10_000))],
    ],
    'a credential call left open over the window' => [
        'a credential call left open over the window',
        ['$pdo = new PDO(', ...array_fill(0, 10, str_repeat("('a', ", 10_000))],
        ['$pdo = new PDO(', ...array_fill(0, 10, str_repeat("('[REDACTED]', ", 10_000))],
    ],
    'lookups repeated inside a sensitive call' => [
        'lookups repeated inside a sensitive call',
        ['setToken(', ...array_fill(0, 10, str_repeat("env( 'A', 'b'), ", 5_000))],
        ['setToken(', ...array_fill(0, 10, str_repeat("env( 'A', '[REDACTED]'), ", 5_000))],
    ],
    'long blanks around a lookup' => [
        'long blanks around a lookup',
        ["'password' => env".str_repeat(' ', 50_000).'('.str_repeat(' ', 50_000)."'A'".str_repeat(' ', 50_000).')'],
        ["'password' => [REDACTED]".str_repeat(' ', 50_000).'('.str_repeat(' ', 50_000)."'A'".str_repeat(' ', 50_000).')'],
    ],
    'many literals after blanks' => [
        'many literals after blanks',
        ["'password' => f(".str_repeat("   'a'", 20_000)],
        ["'password' => f(".str_repeat("   '[REDACTED]'", 20_000)],
    ],
    'block comments inside a sensitive call' => [
        'block comments inside a sensitive call',
        ['setToken(', ...array_fill(0, 10, str_repeat("/* a */ 'b', ", 5_000))],
        ['setToken(', ...array_fill(0, 10, str_repeat("/* a */ '[REDACTED]', ", 5_000))],
    ],
    'sensitive calls each opening a comment' => [
        'sensitive calls each opening a comment',
        [str_repeat('setToken( // ', 5_000), str_repeat('setToken(/* ', 5_000), "*/ 'x'"],
        [str_repeat('setToken( // ', 5_000), str_repeat('setToken(/* ', 5_000), "*/ '[REDACTED]'"],
    ],
    'a name and a long run of blanks' => [
        'a name and a long run of blanks',
        array_fill(0, 11, "'password' => a.b".str_repeat(" \t", 25_000).'x'),
        array_fill(0, 11, "'password' => [REDACTED]".str_repeat(" \t", 25_000).'x'),
    ],
    'a name spaced from its call' => [
        'a name spaced from its call',
        array_fill(0, 11, "'password' => f".str_repeat(' ', 50_000)."('x')"),
        array_fill(0, 11, "'password' => [REDACTED]".str_repeat(' ', 50_000)."('[REDACTED]')"),
    ],
    'a PDO subclass with many parent calls' => [
        'a PDO subclass with many parent calls',
        ['class Db extends PDO', ...array_fill(0, 10, str_repeat("parent::__construct('a'); ", 5_000))],
        ['class Db extends PDO', ...array_fill(0, 10, str_repeat("parent::__construct('[REDACTED]'); ", 5_000))],
    ],
    'every line ending in extends' => [
        'every line ending in extends',
        [...array_fill(0, 10, str_repeat('x extends ', 5_000).'extends'), str_repeat(' ', 50_000).'PDOX'],
        [...array_fill(0, 10, str_repeat('x extends ', 5_000).'extends'), str_repeat(' ', 50_000).'PDOX'],
    ],
    'extends and long blank runs on every line' => [
        'extends and long blank runs on every line',
        array_fill(0, 11, str_repeat('extends ', 5_000).'extends'.str_repeat(' ', 50_000).'PDOX'),
        array_fill(0, 11, str_repeat('extends ', 5_000).'extends'.str_repeat(' ', 50_000).'PDOX'),
    ],
    'a block comment left open over the window' => [
        'a block comment left open over the window',
        ['setToken(/*', ...array_fill(0, 10, str_repeat("it's * / ", 10_000))],
        ['setToken(/*', ...array_fill(0, 10, str_repeat("it's * / ", 10_000))],
    ],
    'a fallback and long blanks ending every line' => [
        'a fallback and long blanks ending every line',
        array_fill(0, 11, 'token ??'.str_repeat(' ', 50_000)),
        ['token ??'.str_repeat(' ', 50_000), ...array_fill(0, 10, '[REDACTED] ??'.str_repeat(' ', 50_000))],
    ],
    'sensitive reads ending every line' => [
        'sensitive reads ending every line',
        array_fill(0, 11, '?? $token'.str_repeat(' ', 50_000)),
        array_fill(0, 11, '?? $token'.str_repeat(' ', 50_000)),
    ],
    'many keys on a line that ends in one' => [
        'many keys on a line that ends in one',
        array_fill(0, 11, str_repeat("\$config['token'] + ", 5_000)."\$config['token']"),
        array_fill(0, 11, str_repeat("\$config['token'] + ", 5_000)."\$config['token']"),
    ],
    'an open heredoc' => [
        'an open heredoc',
        ['$secret = <<<EOT', ...array_fill(0, 10, str_repeat('E', 50_000))],
        ['$secret = <<<EOT', ...array_fill(0, 10, '[REDACTED]')],
    ],
]);

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
    'unterminated quoted value' => [
        'unterminated quoted value',
        '"password":"'.str_repeat('a ', 25_000),
        '"password":"[REDACTED]',
    ],
    'quoted value of escaped quotes' => [
        'quoted value of escaped quotes',
        "'token' => '".str_repeat("\\'", 25_000)."'",
        "'token' => '[REDACTED]'",
    ],
    'quoted value of the other quote' => [
        'quoted value of the other quote',
        "'token' => '".str_repeat('"', 50_000)."'",
        "'token' => '[REDACTED]'",
    ],
    'key, comma, value repeated' => [
        'key, comma, value repeated',
        str_repeat("'token', ", 10_000),
        str_repeat("'token', '[REDACTED]', ", 5_000),
    ],
    'whitespace run after a key' => [
        'whitespace run after a key',
        'token'.str_repeat(' ', 50_000).'x',
        'token'.str_repeat(' ', 50_000).'x',
    ],
    'many keys without a separator' => [
        'many keys without a separator',
        str_repeat("'token' ", 10_000),
        str_repeat("'token' ", 10_000),
    ],
    'deeply nested code value' => [
        'deeply nested code value',
        "'password' => ".str_repeat('[', 25_000).str_repeat(']', 25_000).',',
        "'password' => [REDACTED],",
    ],
    'code-shaped value of many calls' => [
        'code-shaped value of many calls',
        'token=a'.str_repeat("('x')", 25_000).' rest',
        'token=[REDACTED] rest',
    ],
    'code-shaped value left open' => [
        'code-shaped value left open',
        'token=a'.str_repeat("(('x', ", 20_000),
        'token=[REDACTED]',
    ],
    'a long chain of names with no call' => [
        'a long chain of names with no call',
        'token='.str_repeat('a.', 25_000),
        'token=[REDACTED]',
    ],
    'a sensitive call left open' => [
        'a sensitive call left open',
        'setToken('.str_repeat("'a', (", 25_000),
        'setToken('.str_repeat("'[REDACTED]', (", 25_000),
    ],
    'sensitive calls repeated' => [
        'sensitive calls repeated',
        str_repeat('getToken()->', 10_000),
        str_repeat('getToken()->', 10_000),
    ],
    'a long name before a paren' => [
        'a long name before a paren',
        str_repeat('a', 50_000).'token(',
        str_repeat('a', 50_000).'token(',
    ],
    'new and a long run of spaces' => [
        'new and a long run of spaces',
        'new'.str_repeat(' ', 50_000).'PDOX(',
        'new'.str_repeat(' ', 50_000).'PDOX(',
    ],
    'credential call names with no paren' => [
        'credential call names with no paren',
        str_repeat('mysqli_connect ', 5_000).'x',
        str_repeat('mysqli_connect ', 5_000).'x',
    ],
    'a credential call left open' => [
        'a credential call left open',
        'new PDO('.str_repeat("'a', (", 25_000),
        'new PDO('.str_repeat("'[REDACTED]', (", 25_000),
    ],
    'comments in a sensitive call' => [
        'comments in a sensitive call',
        'setToken('.str_repeat('/* a */ # b ', 5_000)."\n".str_repeat('setToken(/* ', 5_000),
        'setToken('.str_repeat('/* a */ # b ', 5_000)."\n".str_repeat('setToken(/* ', 5_000),
    ],
    'fallbacks repeated' => [
        'fallbacks repeated',
        str_repeat("'token' ?? ", 10_000).str_repeat('token ?', 10_000),
        str_repeat("'token' ?? '[REDACTED]' ?? ", 5_000).str_repeat('token ?', 10_000),
    ],
    'message keys repeated' => [
        'message keys repeated',
        str_repeat("'password.required' => 'a', 'password.requiredx' => 'b', ", 5_000),
        str_repeat("'password.required' => 'a', 'password.requiredx' => '[REDACTED]', ", 5_000),
    ],
    'call keys before long blanks' => [
        'call keys before long blanks',
        str_repeat("f('token')     ", 10_000)."f('token')".str_repeat(' ', 50_000).'?? x',
        str_repeat("f('token')     ", 10_000)."f('token')".str_repeat(' ', 50_000).'?? [REDACTED]',
    ],
    'call keys with long blanks before the paren' => [
        'call keys with long blanks before the paren',
        str_repeat("f('token'      x ", 10_000)."f('token'".str_repeat(' ', 50_000).') ?? x',
        str_repeat("f('token'      x ", 10_000)."f('token'".str_repeat(' ', 50_000).') ?? [REDACTED]',
    ],
    'exception calls repeated' => [
        'exception calls repeated',
        str_repeat("new TokenException('x') ", 5_000),
        str_repeat("new TokenException('x') ", 5_000),
    ],
    'a long name ending in an exception' => [
        'a long name ending in an exception',
        'setToken'.str_repeat('a', 50_000)."Exception('x')",
        'setToken'.str_repeat('a', 50_000)."Exception('x')",
    ],
    'new before a long run under a key' => [
        'new before a long run under a key',
        'token=new '.str_repeat('a', 50_000),
        'token=[REDACTED] '.str_repeat('a', 50_000),
    ],
    'many code values in a row' => [
        'many code values in a row',
        str_repeat("'token' => \$x, ", 5_000),
        str_repeat("'token' => [REDACTED], ", 5_000),
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
