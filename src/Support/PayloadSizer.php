<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * Enforces the per-field JSON byte budget shared by the capture subsystems
 * (log context/extra, JS-error context, breadcrumb data). Oversized data is
 * replaced wholesale with a `_truncated` marker rather than truncated
 * mid-structure, since partial JSON is invalid.
 *
 * Shared with `ranetrace/ranetrace-laravel`. The marker key and the
 * byte-counting method are part of the wire contract, so there is one of them.
 */
final class PayloadSizer
{
    /**
     * The marker's reason when the data cannot be JSON-encoded at all, in place
     * of the caller's size reason, which would misstate why it went.
     */
    public const string UNENCODABLE_REASON = 'Field could not be encoded as JSON and was removed';

    /**
     * Return $data unchanged when its JSON-encoded byte size is within
     * $maxBytes; otherwise return a `['_truncated' => $reason]` marker.
     *
     * Data that cannot be encoded at all is over every budget: it gets the
     * marker with {@see UNENCODABLE_REASON}. Measured as zero bytes it would be
     * kept, and then fail the encode of its item or of the batch it is sent in.
     *
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    public static function capBytes(array $data, int $maxBytes, string $reason): array
    {
        $bytes = self::encodedBytes($data);

        if ($bytes === null) {
            return ['_truncated' => self::UNENCODABLE_REASON];
        }

        if ($bytes > $maxBytes) {
            return ['_truncated' => $reason];
        }

        return $data;
    }

    /**
     * The byte length of PHP's default JSON encoding of the value, or null when
     * it cannot be encoded at all. That is how the endpoints measure: they
     * decode the batch and encode each item again, so escaped slashes and
     * `\uXXXX` count.
     *
     * Measured with `mb_strlen(..., '8bit')` rather than `strlen`, which the
     * repo's Pint `mb_str_functions` rule would rewrite to a character count,
     * breaking every byte budget on multibyte data.
     */
    public static function encodedBytes(mixed $value): ?int
    {
        $encoded = json_encode($value);

        return $encoded === false ? null : mb_strlen($encoded, '8bit');
    }
}
