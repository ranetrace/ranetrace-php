<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * The host's user id as the backend takes it on every ingest endpoint: an int,
 * or a string of at most 255 characters. Any other value rejects the whole
 * batch it travels in, so the item builders send no user rather than one the
 * backend would refuse. The id is the host's own, and a host can report
 * anything here, so this is checked where each item is built.
 */
final class UserId
{
    /** The longest string the backend takes, for a user id and an error item's user email alike. */
    public const int MAX_LENGTH = 255;

    /**
     * The id unchanged when the backend takes it, null otherwise.
     */
    public static function accepted(mixed $id): int|string|null
    {
        if (is_int($id) || (is_string($id) && mb_strlen($id) <= self::MAX_LENGTH)) {
            return $id;
        }

        return null;
    }
}
