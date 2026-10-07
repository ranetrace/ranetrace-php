<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * The host's user id as the backend takes it on every ingest endpoint: an int,
 * or a string of at most 255 characters. Any other value refuses the item it
 * travels in, losing the whole report for its user, so the item builders send
 * no user rather than one the backend would refuse. The id is the host's own, and a host can report
 * anything here, so this is checked where each item is built.
 */
final class UserId
{
    /** The longest string the backend takes, for a user id and an error item's user email alike. */
    public const int MAX_LENGTH = 255;

    /**
     * The id when the backend takes it, null otherwise. A string id is sent
     * through {@see Utf8::repair()}, since an id JSON cannot encode fails its
     * batch just as an overlong one does.
     */
    public static function accepted(mixed $id): int|string|null
    {
        if (is_int($id)) {
            return $id;
        }

        if (is_string($id)) {
            $id = Utf8::repair($id);

            return mb_strlen($id) <= self::MAX_LENGTH ? $id : null;
        }

        return null;
    }
}
