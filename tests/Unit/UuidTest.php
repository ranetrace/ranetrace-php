<?php

declare(strict_types=1);

use Ranetrace\Php\Support\Uuid;

/**
 * The form the API's `uuid` rule accepts, with the version and variant a
 * random UUID declares.
 */
test('it makes a lowercase version 4 uuid', function (): void {
    expect(Uuid::v4())->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D');
});

test('it does not make the same uuid twice', function (): void {
    $made = [];

    for ($index = 0; $index < 5_000; $index++) {
        $made[Uuid::v4()] = true;
    }

    expect($made)->toHaveCount(5_000);
});
