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

/**
 * The frame rules are the lint's spelling of checks the backend makes across
 * fields: `present`, `increasing`, `null_with` and `null_when_true`.
 */
test('a present field may be null but not missing', function (): void {
    $fields = ['message' => ['present' => true, 'type' => 'string']];

    expect(DescriptorValidator::violations($fields, ['message' => null]))->toBe([])
        ->and(DescriptorValidator::violations($fields, ['message' => '']))->toBe([])
        ->and(DescriptorValidator::violations($fields, []))->toBe(["'message' must be present"]);
});

test('an increasing list needs distinct integer keys that only go up', function (array $frames, int $violations): void {
    $fields = ['frames' => ['type' => 'array', 'increasing' => 'index']];

    expect(DescriptorValidator::violations($fields, ['frames' => $frames]))->toHaveCount($violations);
})->with([
    'with a gap' => [[['index' => 0], ['index' => 1], ['index' => 70]], 0],
    'empty' => [[], 0],
    'repeated' => [[['index' => 0], ['index' => 0]], 1],
    'going down' => [[['index' => 3], ['index' => 2]], 1],
    'not an integer' => [[['index' => '0']], 1],
]);

test('a null_with field is null exactly when its sibling is', function (array $item, int $violations): void {
    $fields = [
        'frames' => ['type' => 'array'],
        'frames_omitted' => ['type' => 'integer', 'null_with' => 'frames'],
    ];

    expect(DescriptorValidator::violations($fields, $item))->toHaveCount($violations);
})->with([
    'both set' => [['frames' => [], 'frames_omitted' => 0], 0],
    'both null' => [['frames' => null, 'frames_omitted' => null], 0],
    'both missing' => [[], 0],
    'count without frames' => [['frames' => null, 'frames_omitted' => 3], 1],
    'frames without count' => [['frames' => [], 'frames_omitted' => null], 1],
]);

test('a null_when_true field must be null when its sibling is true, at any depth', function (array $frame, int $violations): void {
    $fields = [
        'previous.*.frames.*.is_vendor' => ['type' => 'boolean'],
        'previous.*.frames.*.source' => ['type' => 'array', 'null_when_true' => 'is_vendor'],
    ];

    expect(DescriptorValidator::violations($fields, ['previous' => [['frames' => [$frame]]]]))->toHaveCount($violations);
})->with([
    'vendor without source' => [['is_vendor' => true, 'source' => null], 0],
    'app with source' => [['is_vendor' => false, 'source' => ['start_line' => 1, 'lines' => ['x']]], 0],
    'vendor with source' => [['is_vendor' => true, 'source' => ['start_line' => 1, 'lines' => ['x']]], 1],
]);
