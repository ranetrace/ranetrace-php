<?php

declare(strict_types=1);

use Ranetrace\Php\Contract\WireContract;
use Ranetrace\Php\Tests\Contract\DescriptorValidator;

/**
 * The fixtures are shipped for other repositories to test against, and the
 * backend application POSTs these very examples at its real endpoints. An
 * example that breaks its own spec would send the next reader chasing a
 * contract violation that only ever existed in this file.
 */
test('every example satisfies the field spec it ships with', function (string $type): void {
    $spec = WireContract::item($type);

    expect($spec['examples'])->toBeArray()
        ->and(array_keys($spec['examples']))->toContain('minimal', 'full');

    $violations = [];

    foreach ($spec['examples'] as $name => $example) {
        foreach (DescriptorValidator::violations(
            $spec['fields'],
            $example,
            ($spec['strict_fields'] ?? false) === true,
            array_keys($spec['legacy_fields'] ?? []),
        ) as $violation) {
            $violations[] = "{$type}.{$name}: {$violation}";
        }
    }

    expect($violations)->toBe([]);
})->with(WireContract::itemTypes());

test('every item fixture declares its own type and wrapper key', function (string $type): void {
    $spec = WireContract::item($type);

    expect($spec['type'])->toBe($type)
        ->and($spec['wrapper'])->toBe(WireContract::endpoints()['endpoints'][$type]['wrapper']);
})->with(WireContract::itemTypes());

test('the errors fixture keeps laravel_version out of the canonical field set', function (): void {
    $spec = WireContract::item('errors');

    expect(DescriptorValidator::topLevelKeys($spec['fields']))->not->toContain('laravel_version')
        ->and($spec['legacy_fields'])->toHaveKey('laravel_version');
});

test('the errors fixture pins the nineteen canonical keys', function (): void {
    expect(DescriptorValidator::topLevelKeys(WireContract::item('errors')['fields']))->toHaveCount(19);
});
