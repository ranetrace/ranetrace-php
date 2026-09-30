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
