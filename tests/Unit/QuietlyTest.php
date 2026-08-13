<?php

declare(strict_types=1);

use Ranetrace\Php\Support\Quietly;

it('returns whatever the callback returns', function (): void {
    expect(Quietly::call(static fn (): string => 'value'))->toBe('value');
});

it('mutes a warning instead of letting the host error handler see it', function (): void {
    $seen = [];

    set_error_handler(static function (int $number, string $message) use (&$seen): bool {
        $seen[] = $message;

        return true;
    });

    try {
        $result = Quietly::call(static fn (): mixed => file_get_contents(tempDirectory().'/absent.json'));
    } finally {
        restore_error_handler();
    }

    // The host handler must stay untouched: a host that routes its logs back
    // into Ranetrace would capture the warning, buffer it and fail the same way.
    expect($seen)->toBe([])
        ->and($result)->toBeFalse();
});

it('turns a throwing callback into false', function (): void {
    expect(Quietly::call(static fn (): mixed => throw new RuntimeException('boom')))->toBeFalse();
});

it('restores the previous error handler even when the callback throws', function (): void {
    $handler = static fn (): bool => true;

    set_error_handler($handler);

    try {
        Quietly::call(static fn (): mixed => throw new RuntimeException('boom'));

        // set_error_handler returns the handler it replaced, which is the one
        // that must be back in place.
        expect(set_error_handler(static fn (): bool => true))->toBe($handler);
        restore_error_handler();
    } finally {
        restore_error_handler();
    }
});
