<?php

declare(strict_types=1);

use Ranetrace\Php\Tests\Contract\DescriptorValidator;

/**
 * The union `type` is the lint's own notation, so what it accepts is pinned
 * here rather than left to whichever fixture happens to use it.
 */
test('a union type accepts a value of any one of its members', function (mixed $value): void {
    $fields = ['user_id' => ['required' => false, 'type' => ['integer', 'string'], 'max' => 255]];

    expect(DescriptorValidator::violations($fields, ['user_id' => $value]))->toBe([]);
})->with([
    'integer above the string bound' => [4211],
    'string at the bound' => [str_repeat('a', 255)],
    'null' => [null],
]);

test('a union type rejects a value of no member and a string past its bound', function (mixed $value): void {
    $fields = ['user_id' => ['required' => false, 'type' => ['integer', 'string'], 'max' => 255]];

    expect(DescriptorValidator::violations($fields, ['user_id' => $value]))->toHaveCount(1);
})->with([
    'boolean' => [true],
    'float' => [4211.5],
    'array' => [[1, 2]],
    'string past the bound' => [str_repeat('a', 256)],
]);

/**
 * `keys` is the lint's spelling of Laravel's `array:id,email`: an array whose
 * keys are all in the list, so one unknown key rejects the item.
 */
test('a keys list accepts an array whose keys are all in it', function (array $user): void {
    $fields = ['user' => ['required' => false, 'type' => 'array', 'keys' => ['id', 'email']]];

    expect(DescriptorValidator::violations($fields, ['user' => $user]))->toBe([]);
})->with([
    'every key' => [['id' => 7, 'email' => null]],
    'some of the keys' => [['id' => 7]],
    'no keys' => [[]],
]);

test('a keys list rejects an array with a key outside it', function (array $user): void {
    $fields = ['user' => ['required' => false, 'type' => 'array', 'keys' => ['id', 'email']]];

    expect(DescriptorValidator::violations($fields, ['user' => $user]))->toHaveCount(1);
})->with([
    'an extra key' => [['id' => 7, 'email' => null, 'name' => 'Jane']],
    'a list' => [[7]],
]);

/**
 * `max_depth` and `max_json_bytes` are the lint's spelling of the backend's
 * custom bounds on a free-shape array: how deeply it nests, where a flat
 * `{"a": 1}` is one level, and how many bytes it takes JSON-encoded.
 */
test('a depth bound accepts an array nested exactly that deep', function (array $value): void {
    $fields = ['data' => ['required' => false, 'type' => 'array', 'max_depth' => 2]];

    expect(DescriptorValidator::violations($fields, ['data' => $value]))->toBe([]);
})->with([
    'flat' => [['a' => 1]],
    'two levels' => [['a' => ['b' => 1]]],
    'an empty array on the second level' => [['a' => []]],
    'empty' => [[]],
]);

test('a depth bound rejects an array nested deeper', function (): void {
    $fields = ['data' => ['required' => false, 'type' => 'array', 'max_depth' => 2]];

    expect(DescriptorValidator::violations($fields, ['data' => ['a' => ['b' => ['c' => 1]]]]))->toHaveCount(1)
        ->and(DescriptorValidator::violations($fields, ['data' => ['a' => ['b' => []]]]))->toHaveCount(1);
});

test('an encoded size bound counts the bytes of the JSON encoding', function (): void {
    $fields = ['data' => ['required' => false, 'type' => 'array', 'max_json_bytes' => 10]];

    expect(DescriptorValidator::violations($fields, ['data' => ['a' => 'xx']]))->toBe([])
        ->and(DescriptorValidator::violations($fields, ['data' => ['a' => 'xxx']]))->toHaveCount(1)
        ->and(DescriptorValidator::violations($fields, ['data' => ['a' => 'é']]))->toHaveCount(1);
});
