<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * Makes the SDK's identifiers: the `id` an error item, an event and a
 * JavaScript error item carry to the API, and the spool envelope's own id.
 *
 * It is one function rather than a dependency on `ramsey/uuid`, because all
 * either id has to be is unique.
 */
final class Uuid
{
    /**
     * A random version-4 UUID, in the lowercase 8-4-4-4-12 form the API's
     * `uuid` rule accepts.
     */
    public static function v4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

        $hex = bin2hex($bytes);

        return sprintf(
            '%s-%s-%s-%s-%s',
            mb_substr($hex, 0, 8),
            mb_substr($hex, 8, 4),
            mb_substr($hex, 12, 4),
            mb_substr($hex, 16, 4),
            mb_substr($hex, 20, 12),
        );
    }
}
