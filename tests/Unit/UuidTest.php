<?php

declare(strict_types=1);

use Ranetrace\Php\Support\Uuid;

/**
 * The form the API's `uuid` rule accepts, with the version and variant a
 * random UUID declares.
 */
test('it makes a lowercase version 4 uuid', function (): void {
    expect(Uuid::v4())->toMatch(UUID_V4_PATTERN);
});

test('it does not make the same uuid twice', function (): void {
    $made = [];

    for ($index = 0; $index < 5_000; $index++) {
        $made[Uuid::v4()] = true;
    }

    expect($made)->toHaveCount(5_000);
});
