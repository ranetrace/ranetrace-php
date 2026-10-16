<?php

declare(strict_types=1);

use Ranetrace\Php\Contract\WireContract;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\Scrubber;
use Ranetrace\Php\Support\SecretScrubber;
use Ranetrace\Php\Tests\Contract\DescriptorValidator;

/**
 * The lines above a source window that are scrubbed with it, so a secret whose
 * key, heredoc opener or call opened above the window's first line is still
 * caught. Every window here is a previous exception's throw site moved onto
 * the line under test, which is the one source the builder reads at any line
 * of any file and returns with its start line.
 */

/**
 * A throwable whose throw site is $line of $file.
 */
function thrownAt(string $file, int $line): RuntimeException
{
    $throwable = new RuntimeException('inner');
    (new ReflectionProperty(Exception::class, 'file'))->setValue($throwable, $file);
    (new ReflectionProperty(Exception::class, 'line'))->setValue($throwable, $line);

    return $throwable;
}

/**
 * Write $lines as a project file, one entry per line, and return its path.
 *
 * @param  list<string>  $lines
 */
function lookbehindFile(string $root, array $lines): string
{
    return writeProjectFile($root, 'app/Lookbehind.php', implode("\n", $lines)."\n");
}

/**
 * The payload of an error whose previous exception was thrown at $line of a
 * file holding $lines.
 *
 * @param  list<string>  $lines
 * @return array<string, mixed>
 */
function lookbehindPayload(array $lines, int $line, ?Scrubber $scrubber = null, ?string $root = null): array
{
    $root ??= frameProject();
    $file = lookbehindFile($root, $lines);

    return framePayload(frameBuilder($root, [], [], $scrubber), new RuntimeException('outer', 0, thrownAt($file, $line)));
}

/**
 * The source window cut around $line of a file holding $lines.
 *
 * @param  list<string>  $lines
 * @return array{start_line: int, lines: list<string>}|null
 */
function lookbehindWindow(array $lines, int $line, ?Scrubber $scrubber = null): ?array
{
    return lookbehindPayload($lines, $line, $scrubber)['previous'][0]['source'];
}

/**
 * $count lines that read `line N`, numbered from $from.
 *
 * @return list<string>
 */
function numberedLines(int $count, int $from = 1): array
{
    return array_map(static fn (int $number): string => "line {$number}", range($from, $from + $count - 1));
}

/**
 * A file whose heredoc on `$password` opens $gap lines above the first line of
 * the window cut around the returned line, with a plain body running through
 * the window.
 *
 * @return array{0: list<string>, 1: int}
 */
function heredocOpenedAbove(int $gap): array
{
    $windowStart = 2 + $gap;

    return [
        ['<?php', '$password = <<<EOT', ...array_fill(0, $windowStart + 8, 'correct horse battery staple'), 'EOT;', 'return $password;'],
        $windowStart + 5,
    ];
}

/**
 * A scrubber whose `scrubSource()` is $scrubSource, scrubbing the rest for
 * real.
 *
 * @param  Closure(list<string>): list<string>  $scrubSource
 */
function sourceScrubber(Closure $scrubSource): Scrubber
{
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    return new class(new SecretScrubber($config, new InternalLogger($config)), $scrubSource) implements Scrubber
    {
        public function __construct(private SecretScrubber $real, private Closure $scrubSource) {}

        public function scrubString(string $value): string
        {
            return $this->real->scrubString($value);
        }

        public function scrubSource(array $lines): array
        {
            return ($this->scrubSource)($lines);
        }

        public function scrubUrl(?string $url): ?string
        {
            return $this->real->scrubUrl($url);
        }

        public function scrubUrlPath(?string $url, array|callable|null $sensitiveValues = null): ?string
        {
            return $this->real->scrubUrlPath($url, $sensitiveValues);
        }

        public function scrubDeep(mixed $data, array|callable|null $sensitiveValues = null): mixed
        {
            return $this->real->scrubDeep($data, $sensitiveValues);
        }
    };
}

test('a heredoc on a sensitive key opened above the window has its body redacted inside the window', function (): void {
    [$lines, $line] = heredocOpenedAbove(1);

    $window = lookbehindWindow($lines, $line);

    expect($window)->toBe([
        'start_line' => 3,
        'lines' => array_fill(0, 11, '[REDACTED]'),
    ]);
});

test('the literal arguments of a sensitive call opened above the window are redacted inside the window', function (): void {
    $lines = [
        '<?php',
        '$client->setCredentials(',
        ...array_fill(0, 7, '    $option,'),
        "    'service-user',",
        "    'plain-pass-in-window',",
        ');',
    ];

    $window = lookbehindWindow($lines, 11);

    expect($window)->toBe([
        'start_line' => 6,
        'lines' => [
            '    $option,',
            '    $option,',
            '    $option,',
            '    $option,',
            "    '[REDACTED]',",
            "    '[REDACTED]',",
            ');',
        ],
    ]);
});

test('a value on the first line of the window is redacted when the line above ends in its sensitive key', function (): void {
    $lines = [
        '<?php',
        '$config = [',
        "    'password' =>",
        "        'next-line-secret',",
        "    'region' => 'eu',",
        '];',
        ...array_fill(0, 6, '// filler'),
    ];

    $window = lookbehindWindow($lines, 9);

    expect($window['start_line'])->toBe(4)
        ->and($window['lines'][0])->toBe("        '[REDACTED]',")
        ->and($window['lines'][1])->toBe("    'region' => 'eu',")
        ->and($window['lines'])->toHaveCount(9);
});

test('a construct opened up to fifty lines above the window is caught and one opened further up is not', function (int $gap, bool $caught): void {
    [$lines, $line] = heredocOpenedAbove($gap);

    $window = lookbehindWindow($lines, $line);

    expect($window['start_line'])->toBe(2 + $gap)
        ->and($window['lines'])->toBe(array_fill(0, 11, $caught ? '[REDACTED]' : 'correct horse battery staple'));
})->with([
    'fifty lines above' => [50, true],
    'fifty-one lines above' => [51, false],
]);

test('a window at the top, in the middle and at the end of a file holds exactly its own lines', function (int $line, int $startLine, int $count): void {
    $window = lookbehindWindow(numberedLines(100), $line);

    expect($window)->toBe([
        'start_line' => $startLine,
        'lines' => numberedLines($count, $startLine),
    ]);
})->with([
    'top of the file' => [3, 1, 11],
    'first line' => [1, 1, 11],
    'first line with a full lookbehind' => [56, 51, 11],
    'middle of the file' => [80, 75, 11],
    'last line but one' => [99, 94, 7],
    'last line' => [100, 95, 6],
]);

test('the scrubber is handed up to fifty lines above the window together with the window', function (int $line, int $firstGiven, int $count): void {
    $given = [];
    $scrubber = sourceScrubber(static function (array $lines) use (&$given): array {
        if (str_starts_with($lines[0] ?? '', 'line ')) {
            $given[] = $lines;
        }

        return $lines;
    });

    lookbehindWindow(numberedLines(100), $line, $scrubber);

    expect($given)->toHaveCount(1)
        ->and($given[0])->toBe(numberedLines($count, $firstGiven));
})->with([
    'a full lookbehind' => [80, 25, 61],
    'a lookbehind clamped at line 1' => [30, 1, 35],
    'no lookbehind at the top' => [3, 1, 11],
]);

test('a scrubber that hands back one window of lines without the lookbehind costs that source, never the report', function (): void {
    $root = frameProject();
    $scrubber = sourceScrubber(static fn (array $lines): array => array_slice($lines, -11));

    $payload = lookbehindPayload(numberedLines(100), 80, $scrubber, $root);

    expect($payload['message'])->toBe('outer')
        ->and($payload['previous'][0]['message'])->toBe('inner')
        ->and($payload['previous'][0]['line'])->toBe(80)
        ->and($payload['previous'][0]['source'])->toBeNull()
        ->and(frameDiagnostics($root))->toContain('The scrubber returned 11 lines for a window of 61')
        ->and(DescriptorValidator::violations(WireContract::item('errors')['fields'], $payload, true))->toBe([]);
});

test('an opener misread in the lookbehind redacts the window rather than misnumbering or dropping it', function (): void {
    // A heredoc opener that never closes, here in a comment, takes every line
    // after it as body. That over-redacts the window, which fails safe.
    $lines = ['<?php', '// $password = <<<EOT', ...numberedLines(98, 3)];

    $window = lookbehindWindow($lines, 30);

    expect($window)->toBe([
        'start_line' => 25,
        'lines' => array_fill(0, 11, '[REDACTED]'),
    ]);
});

test('a construct opened on line 1 is caught by a lookbehind clamped at the start of the file', function (): void {
    $lines = ['<?php $password = <<<EOT', ...array_fill(0, 20, 'correct horse battery staple'), 'EOT;'];

    $window = lookbehindWindow($lines, 11);

    expect($window)->toBe([
        'start_line' => 6,
        'lines' => array_fill(0, 11, '[REDACTED]'),
    ]);
});

test('an opener past the line cap in the lookbehind still counts, since lines are capped only after scrubbing', function (): void {
    $lines = ['<?php', '/* '.str_repeat('x', 5_000).' */ $password = <<<EOT', ...array_fill(0, 20, 'correct horse battery staple'), 'EOT;'];

    $window = lookbehindWindow($lines, 12);

    expect($window['start_line'])->toBe(7)
        ->and($window['lines'])->toBe(array_fill(0, 11, '[REDACTED]'));
});

test('windows cut from one read of a file each get their own lookbehind and their own line numbers', function (): void {
    $root = frameProject();
    [$lines] = heredocOpenedAbove(30);
    $file = lookbehindFile($root, $lines);
    $outer = new RuntimeException('outer', 0, thrownAt($file, 2));
    (new ReflectionProperty(Exception::class, 'file'))->setValue($outer, $file);
    (new ReflectionProperty(Exception::class, 'line'))->setValue($outer, 40);

    $payload = framePayload(frameBuilder($root), $outer);

    expect($payload['context'])->toBe(implode("\n", [...array_fill(0, 8, '[REDACTED]'), 'EOT;', 'return $password;'])."\n")
        ->and($payload['highlight_line'])->toBe(6)
        ->and($payload['previous'][0]['source'])->toBe([
            'start_line' => 1,
            'lines' => ['<?php', '$password = <<<EOT', ...array_fill(0, 9, '[REDACTED]')],
        ])
        ->and((string) json_encode($payload))->not->toContain('correct horse');
});

test('a lookbehind of near megabyte lines is scrubbed in bounded time and only the window is capped and sent', function (): void {
    $root = frameProject();
    $long = str_repeat('a', 19_000);
    $lines = ['<?php', ...array_fill(0, 50, "\$text = '{$long}';"), ...numberedLines(11, 52)];

    $started = hrtime(true);
    $payload = lookbehindPayload($lines, 57, null, $root);
    $elapsedMilliseconds = (hrtime(true) - $started) / 1_000_000;

    expect(filesize($root.'/app/Lookbehind.php'))->toBeLessThan(1_048_576)
        ->and($payload['previous'][0]['source'])->toBe(['start_line' => 52, 'lines' => numberedLines(11, 52)])
        ->and($elapsedMilliseconds)->toBeLessThan(1_000);
});

test('a private key that began above a window inside its body has every body line redacted, short ones too', function (): void {
    // A body line too short for the line-by-line base64 rule is caught only
    // by knowing the window sits between the key's markers.
    $body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj';
    $lines = ['<?php', '$pem = <<<PEM', '-----BEGIN PRIVATE KEY-----', ...array_fill(0, 8, $body), 'q8Zx', ...array_fill(0, 8, $body), '-----END PRIVATE KEY-----', 'PEM;'];

    $window = lookbehindWindow($lines, 12);

    expect($window)->toBe([
        'start_line' => 7,
        'lines' => array_fill(0, 11, '[REDACTED]'),
    ]);
});

test('a lookbehind that starts inside a private key leaves the code after the key readable', function (): void {
    $body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj';
    $lines = ['<?php', '$pem = <<<PEM', '-----BEGIN PRIVATE KEY-----', ...array_fill(0, 60, $body), '-----END PRIVATE KEY-----', 'PEM;', ...numberedLines(20, 66)];

    $window = lookbehindWindow($lines, 75);

    expect($window)->toBe([
        'start_line' => 70,
        'lines' => numberedLines(11, 70),
    ]);
});

test('a sensitive call left open in the lookbehind costs the literals in the window and keeps the code', function (): void {
    $lines = ['<?php', '// $client->setCredentials(', ...numberedLines(20, 3), '$region = \'eu\';', ...numberedLines(10, 24)];

    $window = lookbehindWindow($lines, 23);

    expect($window['start_line'])->toBe(18)
        ->and($window['lines'])->toHaveCount(11)
        ->and($window['lines'][0])->toBe('line 18')
        ->and($window['lines'][5])->toBe("\$region = '[REDACTED]';");
});

test('a line past the end of the file gets no source, though lines above it are in reach of the lookbehind', function (int $line): void {
    $scrubbed = 0;
    $scrubber = sourceScrubber(static function (array $lines) use (&$scrubbed): array {
        $scrubbed += str_starts_with($lines[0] ?? '', 'line ') ? 1 : 0;

        return $lines;
    });

    expect(lookbehindWindow(numberedLines(100), $line, $scrubber))->toBeNull()
        ->and($scrubbed)->toBe(0);
})->with([
    'just past the window reach' => [107],
    'well within the lookbehind reach' => [130],
]);
