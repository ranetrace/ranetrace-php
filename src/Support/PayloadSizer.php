<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * Enforces the per-field JSON byte budget shared by the capture subsystems
 * (log context/extra, JS-error context, breadcrumb data). Oversized data is
 * replaced wholesale with a `_truncated` marker rather than truncated
 * mid-structure, since partial JSON is invalid.
 *
 * Shared with `ranetrace/ranetrace-laravel`, whose copy this replaced. The
 * marker key and the byte-counting method are part of the wire contract, so
 * there is one of them; the signature is narrower than the copy's was (`array`,
 * not `mixed`), which is all any call site ever passed.
 */
final class PayloadSizer
{
    /**
     * Return $data unchanged when its JSON-encoded byte size is within
     * $maxBytes; otherwise return a `['_truncated' => $reason]` marker.
     *
     * Byte size is measured with `mb_strlen(..., '8bit')` (NOT `strlen`: the
     * repo's Pint `mb_str_functions` rule would rewrite `strlen` to a
     * char-counting `mb_strlen`, breaking the byte budget on multibyte data).
     *
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    public static function capBytes(array $data, int $maxBytes, string $reason): array
    {
        if (mb_strlen((string) json_encode($data), '8bit') > $maxBytes) {
            return ['_truncated' => $reason];
        }

        return $data;
    }
}
