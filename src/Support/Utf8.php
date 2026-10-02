<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * Makes captured text valid UTF-8, replacing each invalid sequence with U+FFFD.
 *
 * The wire is JSON, and `json_encode` refuses the whole value it is handed when
 * a single string in it, or a single array key, is not UTF-8. Captured text
 * carries such bytes in practice: a database driver message in latin1, a source
 * file saved in a legacy encoding, a header or a URL a client sent raw. One bad
 * byte then costs its item at the buffer or, in a host whose buffer does not
 * encode, the whole batch it is sent in. So every string the shared item
 * builders put in an item passes through here first, before it is scrubbed,
 * capped or measured, which keeps every cap counted on the text that is sent.
 *
 * The replacement is U+FFFD rather than `?`, so a reader can tell a lost byte
 * from a real question mark. `mb_scrub()` and `mb_convert_encoding()` substitute
 * whatever `mb_substitute_character()` holds, which is process-global and `?`
 * by default, and a library must not change it under its host. JSON's own
 * substitute flag gives U+FFFD on every call regardless of that setting.
 */
final class Utf8
{
    /**
     * The string unchanged when it is valid UTF-8, otherwise a copy with each
     * invalid sequence replaced by U+FFFD.
     */
    public static function repair(string $value): string
    {
        if (mb_check_encoding($value, 'UTF-8')) {
            return $value;
        }

        $decoded = json_decode((string) json_encode($value, JSON_INVALID_UTF8_SUBSTITUTE));

        return is_string($decoded) ? $decoded : '';
    }

    /**
     * {@see repair()} applied to a string, or to every string key and string
     * value of an array at any depth. Every other value is returned as it is,
     * so the shape and the types of the data do not change.
     *
     * Recursion is unbounded, so callers hand it data that is already
     * depth-bounded, such as the output of
     * {@see DataSanitizer::sanitizeForSerialization()}.
     */
    public static function repairDeep(mixed $value): mixed
    {
        if (is_string($value)) {
            return self::repair($value);
        }

        if (! is_array($value)) {
            return $value;
        }

        $repaired = [];

        foreach ($value as $key => $item) {
            $repaired[is_string($key) ? self::repair($key) : $key] = self::repairDeep($item);
        }

        return $repaired;
    }

    /**
     * {@see repair()} for a nullable string.
     */
    public static function repairNullable(?string $value): ?string
    {
        return $value === null ? null : self::repair($value);
    }
}
