<?php

declare(strict_types=1);

use Ranetrace\Php\Support\Utf8;

test('a valid string comes back unchanged', function (string $value): void {
    expect(Utf8::repair($value))->toBe($value);
})->with([
    'empty' => [''],
    'ascii' => ['plain text'],
    'multibyte' => ['Jos€ 日本 😀'],
]);

test('each invalid sequence is replaced by U+FFFD, never by a question mark', function (string $value, string $expected): void {
    expect(Utf8::repair($value))->toBe($expected);
})->with([
    'a latin1 byte' => ["a\xB1b", "a\u{FFFD}b"],
    'two stray bytes' => ["\xFF\xFE", "\u{FFFD}\u{FFFD}"],
    'a sequence cut short' => ["x\xE2\x82", "x\u{FFFD}"],
    'an overlong encoding' => ["\xC0\xAF", "\u{FFFD}\u{FFFD}"],
]);

test('repairing leaves the process-wide substitute character alone', function (): void {
    $before = mb_substitute_character();
    mb_substitute_character(0x2A);

    try {
        expect(Utf8::repair("a\xB1"))->toBe("a\u{FFFD}")
            ->and(mb_substitute_character())->toBe(0x2A);
    } finally {
        mb_substitute_character($before);
    }
});

test('array keys and values are repaired at every depth, and nothing else changes', function (): void {
    $repaired = Utf8::repairDeep([
        "k\xB1" => ['nested' => ['deeper' => "v\xB1"]],
        'list' => [1, 2.5, true, null, "x\xB1"],
        7 => 'int key',
    ]);

    expect($repaired)->toBe([
        "k\u{FFFD}" => ['nested' => ['deeper' => "v\u{FFFD}"]],
        'list' => [1, 2.5, true, null, "x\u{FFFD}"],
        7 => 'int key',
    ]);
});

test('a value that is neither a string nor an array is returned as it is', function (mixed $value): void {
    expect(Utf8::repairDeep($value))->toBe($value);
})->with([
    'int' => [42],
    'float' => [1.5],
    'bool' => [false],
    'null' => [null],
]);
