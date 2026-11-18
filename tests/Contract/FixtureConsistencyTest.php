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
        ) as $violation) {
            $violations[] = "{$type}.{$name}: {$violation}";
        }
    }

    expect($violations)->toBe([]);
})->with(WireContract::describedItemTypes());

test('every item fixture declares its own type and wrapper key', function (string $type): void {
    $spec = WireContract::item($type);

    expect($spec['type'])->toBe($type)
        ->and($spec['wrapper'])->toBe(WireContract::endpoints()['endpoints'][$type]['wrapper'])
        ->and($spec['wrapper'])->toBe(WireContract::envelope()['wrappers'][$type]);
})->with(WireContract::describedItemTypes());

test('the page visit fixture refuses what the endpoint refuses', function (array $change, string $violation): void {
    $spec = WireContract::item('page_visits');

    expect(DescriptorValidator::violations($spec['fields'], [...$spec['examples']['full'], ...$change]))
        ->toHaveCount(1)
        ->sequence(fn ($message) => $message->toContain($violation));
})->with([
    'a path one character over its limit' => [['path' => '/'.str_repeat('a', 1024)], "'path'"],
    'a referrer one character over its limit' => [['referrer' => 'https://a.test/'.str_repeat('a', 2034)], "'referrer'"],
    'a campaign value one character over its limit' => [['utm_campaign' => str_repeat('a', 256)], "'utm_campaign'"],
    'a session hash that is not 64 characters' => [['session_id_hash' => 'abc'], "'session_id_hash'"],
    'a lower-case country code' => [['country_code' => 'nl'], "'country_code'"],
    'a device type outside the list' => [['device_type' => 'tv'], "'device_type'"],
    'a score over 100' => [['human_probability_score' => 101], "'human_probability_score'"],
    'a verdict that is not a boolean' => [['verified_human' => 'yes'], "'verified_human'"],
]);

test('the errors fixture keeps the retired laravel_version key out entirely', function (): void {
    // The ingest refuses an error item carrying the key, so the fixture
    // carries no legacy block at all and the key must not creep back into fields.
    $spec = WireContract::item('errors');

    expect(DescriptorValidator::topLevelKeys($spec['fields']))->not->toContain('laravel_version')
        ->and($spec)->not->toHaveKey('legacy_fields');
});

test('the errors fixture pins the twenty-four canonical keys', function (): void {
    expect(DescriptorValidator::topLevelKeys(WireContract::item('errors')['fields']))->toHaveCount(24);
});
