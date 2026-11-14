<?php

declare(strict_types=1);

use Ranetrace\Php\Support\StringLimit;

test('a value within the limit comes back unchanged from every cut', function (string $method, string $value, int $limit): void {
    expect(StringLimit::{$method}($value, $limit))->toBe($value);
})->with([
    'cut' => ['cut'],
    'cutWithSuffix' => ['cutWithSuffix'],
    'cutBytesWithSuffix' => ['cutBytesWithSuffix'],
])->with([
    'under the limit' => ['abc', 20],
    'at the limit' => [str_repeat('a', 20), 20],
    'multibyte, twenty bytes in ten characters' => [str_repeat('é', 10), 20],
]);

test('the plain cut keeps the first characters, counted as characters, and adds no suffix', function (string $value, int $limit, string $expected): void {
    expect(StringLimit::cut($value, $limit))->toBe($expected);
})->with([
    'ascii' => ['abcdefgh', 5, 'abcde'],
    'multibyte' => ['日本語テキスト', 3, '日本語'],
]);

test('the character cut ends in the suffix and is exactly the limit long, suffix included', function (string $value, string $kept): void {
    $cut = StringLimit::cutWithSuffix($value, 30);

    expect($cut)->toBe($kept.StringLimit::SUFFIX)
        ->and(mb_strlen($cut))->toBe(30);
})->with([
    'ascii' => [str_repeat('a', 31), str_repeat('a', 15)],
    'multibyte' => [str_repeat('é', 31), str_repeat('é', 15)],
]);

test('the byte cut ends in the suffix within the byte limit, suffix included, and never splits a character', function (string $value, string $kept): void {
    $cut = StringLimit::cutBytesWithSuffix($value, 30);

    expect($cut)->toBe($kept.StringLimit::SUFFIX)
        ->and(mb_strlen($cut, '8bit'))->toBeLessThanOrEqual(30)
        ->and(mb_check_encoding($cut, 'UTF-8'))->toBeTrue();
})->with([
    'ascii' => [str_repeat('a', 31), str_repeat('a', 15)],
    'two-byte characters' => [str_repeat('é', 16), str_repeat('é', 7)],
    'three-byte characters' => [str_repeat('€', 11), str_repeat('€', 5)],
    'four-byte characters' => [str_repeat('😀', 8), str_repeat('😀', 3)],
]);

test('below the suffix length a suffixed cut drops that many units from the end, so the result is longer than the limit', function (string $method): void {
    expect(StringLimit::{$method}('abcdefghijklmnopqrst', 10))->toBe('abcdefghijklmno'.StringLimit::SUFFIX);
})->with([
    'cutWithSuffix' => ['cutWithSuffix'],
    'cutBytesWithSuffix' => ['cutBytesWithSuffix'],
]);
