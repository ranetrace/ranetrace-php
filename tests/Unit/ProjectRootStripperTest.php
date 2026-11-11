<?php

declare(strict_types=1);

use Ranetrace\Php\Support\ProjectRootStripper;

function stripper(string $root = '/var/www/app'): ProjectRootStripper
{
    return new ProjectRootStripper(testConfig(['project_root' => $root]));
}

test('a path under the project root loses the root wherever it stands in a text', function (string $text, string $expected): void {
    expect(stripper()->strip($text))->toBe($expected);
})->with([
    'a view exception message' => [
        'Undefined variable $user (View: /var/www/app/resources/views/profile.blade.php)',
        'Undefined variable $user (View: resources/views/profile.blade.php)',
    ],
    'a line of a text trace' => [
        '#0 /var/www/app/app/Http/Kernel.php(12): App\Http\Kernel->handle()',
        '#0 app/Http/Kernel.php(12): App\Http\Kernel->handle()',
    ],
    'a closure name' => [
        '{closure:/var/www/app/routes/web.php:12}',
        '{closure:routes/web.php:12}',
    ],
    'a php warning' => [
        'include(/var/www/app/config/missing.php): Failed to open stream: No such file or directory',
        'include(config/missing.php): Failed to open stream: No such file or directory',
    ],
    'a quoted path' => [
        'The file "/var/www/app/storage/logs/laravel.log" could not be opened',
        'The file "storage/logs/laravel.log" could not be opened',
    ],
    'the marker a compiled view ends in' => [
        '<?php /**PATH /var/www/app/resources/views/profile.blade.php ENDPATH**/ ?>',
        '<?php /**PATH resources/views/profile.blade.php ENDPATH**/ ?>',
    ],
    'a file url' => [
        'file:///var/www/app/storage/report.pdf',
        'file://storage/report.pdf',
    ],
    'a path json has escaped' => [
        '{"file":"\/var\/www\/app\/storage\/import.json"}',
        '{"file":"storage\/import.json"}',
    ],
    'two paths in one text' => [
        'copy(/var/www/app/a.txt, /var/www/app/b.txt) failed',
        'copy(a.txt, b.txt) failed',
    ],
]);

test('the root named on its own becomes a marker, since no relative path is left to show', function (string $text, string $expected): void {
    expect(stripper()->strip($text))->toBe($expected);
})->with([
    'at the end of a message' => ['fatal: not a git repository: /var/www/app', 'fatal: not a git repository: [project root]'],
    'at the end of a sentence' => ['Could not write to /var/www/app.', 'Could not write to [project root].'],
    'as an argument in a text trace' => ["Application->__construct('/var/www/app')", "Application->__construct('[project root]')"],
    'with a trailing separator' => ['chdir(/var/www/app/) failed', 'chdir([project root]) failed'],
]);

test('a path that only starts like the root, or holds it further in, is left as it is', function (string $text): void {
    expect(stripper()->strip($text))->toBe($text);
})->with([
    'a longer directory name' => ['/var/www/application/index.php'],
    'a sibling with a suffix' => ['/var/www/app-old/index.php'],
    'a sibling with an extension' => ['/var/www/app.bak/index.php'],
    'the root further into another path' => ['/srv/backup/var/www/app/index.php'],
    'the path of a web url' => ['https://example.test/var/www/app/index.php'],
    'a text that names no path' => ['Call to a member function format() on null'],
]);

test('the root is found whatever separator ends it in the config', function (): void {
    expect(stripper('/var/www/app/')->strip('/var/www/app/app/Foo.php'))->toBe('app/Foo.php');
});

test('a windows root is found under either separator, single or doubled', function (string $text, string $expected): void {
    expect(stripper('C:\inetpub\app')->strip($text))->toBe($expected);
})->with([
    'backslashes' => ['C:\inetpub\app\src\Foo.php(12)', 'src\Foo.php(12)'],
    'forward slashes' => ['C:/inetpub/app/src/Foo.php(12)', 'src/Foo.php(12)'],
    'doubled in a string literal' => ["require 'C:\\\\inetpub\\\\app\\\\src\\\\Foo.php';", "require 'src\\\\Foo.php';"],
]);

test('a root that says nothing, or is the filesystem root, strips nothing', function (string $root): void {
    expect(stripper($root)->strip('The app in /var/www/app/app/Foo.php'))->toBe('The app in /var/www/app/app/Foo.php');
})->with([
    'no root' => [''],
    'the filesystem root' => ['/'],
    'a drive' => ['C:\\'],
    'a relative root, which is also a word' => ['app'],
]);

test('a megabyte of paths that nearly match is read in linear time', function (): void {
    $text = str_repeat('/var/www/ap /var/www/app-old/x.php /var/www/app/', 22_000);
    $started = microtime(true);

    $stripped = stripper()->strip($text);

    expect(microtime(true) - $started)->toBeLessThan(1.0)
        ->and($stripped)->toStartWith('/var/www/ap /var/www/app-old/x.php [project root]/var/www/ap ');
});

test('every string value of a nested array is stripped, and nothing else is touched', function (): void {
    $stripped = stripper()->stripDeep([
        'file' => '/var/www/app/storage/import.csv',
        'rows' => 12,
        'nested' => ['path' => '/var/www/app/storage/tmp', 'ok' => true, 'none' => null],
        '/var/www/app/key' => 'a key is left alone',
    ]);

    expect($stripped)->toBe([
        'file' => 'storage/import.csv',
        'rows' => 12,
        'nested' => ['path' => 'storage/tmp', 'ok' => true, 'none' => null],
        '/var/www/app/key' => 'a key is left alone',
    ]);
});

test('each line of a list of lines is stripped on its own', function (): void {
    expect(stripper()->stripLines([
        "require '/var/www/app/vendor/autoload.php';",
        '$total = $a / $b;',
    ]))->toBe([
        "require 'vendor/autoload.php';",
        '$total = $a / $b;',
    ]);
});

test('a text with invalid bytes in it still loses the root', function (): void {
    expect(stripper()->strip("Bad \xB1 byte in /var/www/app/data.csv"))->toBe("Bad \xB1 byte in data.csv");
});

test('a root holding pattern characters is matched literally', function (): void {
    expect(stripper('/srv/app (v2)+')->strip('/srv/app (v2)+/src/Foo.php and /srv/app (v2)/src'))
        ->toBe('src/Foo.php and /srv/app (v2)/src');
});
