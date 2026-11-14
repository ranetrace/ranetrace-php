<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * Cuts a string to a length limit, the one way every builder in the package
 * does it.
 *
 * Free text that was cut ends in {@see SUFFIX}, so a reader can tell a cut
 * message from one that happened to end there. A name, such as a version, a
 * framework or a channel, is cut with no suffix.
 *
 * Every limit a caller passes is longer than the suffix. Below the suffix's
 * own length the suffixed cuts cannot keep their limit: the length left for
 * the text is then negative, which drops that many characters (or bytes) from
 * the end of the value rather than cutting it to nothing, so the result is
 * longer than the limit.
 *
 * @internal
 */
final class StringLimit
{
    /**
     * Ends a string cut at its limit.
     */
    public const string SUFFIX = '... (truncated)';

    /**
     * The value unchanged when it is at most $maxLength characters, otherwise
     * its first $maxLength characters, with no suffix.
     */
    public static function cut(string $value, int $maxLength): string
    {
        return mb_strlen($value) <= $maxLength ? $value : mb_substr($value, 0, $maxLength);
    }

    /**
     * The value unchanged when it is at most $maxLength characters, otherwise
     * cut so that it, with {@see SUFFIX} appended, is $maxLength characters.
     * The suffix counts inside the limit.
     */
    public static function cutWithSuffix(string $value, int $maxLength): string
    {
        if (mb_strlen($value) <= $maxLength) {
            return $value;
        }

        return mb_substr($value, 0, $maxLength - mb_strlen(self::SUFFIX)).self::SUFFIX;
    }

    /**
     * The value unchanged when it is at most $maxBytes bytes, otherwise cut so
     * that it, with {@see SUFFIX} appended, is at most $maxBytes bytes. The
     * suffix counts inside the limit, and the cut falls on a UTF-8 character
     * boundary, so it can come out a few bytes short of the limit but never
     * splits a character.
     */
    public static function cutBytesWithSuffix(string $value, int $maxBytes): string
    {
        if (mb_strlen($value, '8bit') <= $maxBytes) {
            return $value;
        }

        return mb_strcut($value, 0, $maxBytes - mb_strlen(self::SUFFIX, '8bit'), 'UTF-8').self::SUFFIX;
    }
}
