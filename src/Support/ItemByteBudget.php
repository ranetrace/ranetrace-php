<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * Holds one captured item to the per-item JSON byte budget, on its way to the
 * buffer.
 *
 * Ported from `ranetrace/ranetrace-laravel`
 * (`src/Jobs/BaseRanetraceJob::capItemBytes()`), where every capture path runs
 * through one base job. The budget, the per-field budget, the truncation suffix
 * and the drop decision are shared semantics and must not drift between the two
 * SDKs: the same oversize item has to be shrunk or dropped identically, or the
 * two produce different payloads for the same input and the difference surfaces
 * as a backend rejection rather than as a test failure here.
 *
 * Why the budget exists at all: the worker's batch trimmer always keeps at
 * least one item, because a single item cannot be split. So one item above the
 * budget is sent anyway, draws a 413, and takes the whole batch with it plus a
 * fifteen-minute pause of that type. Each capture path already caps its own
 * free-form fields, but a missing rule on any one of them should not be able to
 * poison a batch of up to a thousand items, so the budget is enforced here as
 * well.
 *
 * This SDK has no base job, and the four capture paths (errors, events, logs,
 * JavaScript relay) each hand their finished item to the buffer themselves, so
 * there is no single call site to hook. The policy therefore lives in this one
 * class and is applied at each of the four buffer handoffs, immediately before
 * `addItem()`. The buffer implementations stay generic on purpose: they are a
 * FIFO spool a host may swap out, and burying wire policy in one of them would
 * lose the policy with it.
 *
 * The handoff is also the right moment because values arriving here have
 * already been scrubbed, so cutting a string cannot expose a secret past a
 * redaction.
 */
final class ItemByteBudget
{
    /**
     * Per-item budget, JSON-encoded. Mirrors `client_item_policy.max_item_bytes`
     * in `contract/envelope.json`, which the contract suite asserts.
     */
    public const int MAX_ITEM_BYTES = 71_680; // 70 KB

    /**
     * Per-field budget, applied only to an item that is already over
     * {@see MAX_ITEM_BYTES}. Free-form strings are where the bulk always is, so
     * shrinking them keeps the item's structure, and its identifying fields,
     * intact.
     */
    public const int MAX_ITEM_FIELD_BYTES = 8_192; // 8 KB

    private const string TRUNCATION_SUFFIX = '... (truncated)';

    private const string FIELD_TRUNCATION_REASON = 'Field exceeded the per-item budget and was removed';

    public function __construct(private readonly InternalLogger $log) {}

    /**
     * Return the item as it should be buffered, or null when it must not be
     * buffered at all.
     *
     * Within budget the item is returned untouched, byte for byte. Over budget,
     * oversize strings are cut to the per-field budget and oversize sub-arrays
     * are replaced wholesale by {@see PayloadSizer::capBytes()} (truncating a
     * structure mid-way yields invalid JSON).
     *
     * An item still over budget after both is dropped outright, and is NOT
     * replaced with a marker payload: the wire shape is an allow-list per type,
     * so a top-level marker key belongs to no type and the backend's strict
     * field matching would reject the item, discarding the whole batch of up to
     * a thousand items and pausing the type, which is precisely the failure
     * this budget exists to prevent. Dropping loses one item and nothing else,
     * and the internal log keeps that loss visible. The nested `_truncated`
     * marker inside a free-shape field is a different thing and stays allowed;
     * `contract/envelope.json` records both rules.
     *
     * @param  string  $type  Buffer type, for the diagnostics entry.
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>|null Null when the item is irreducibly over budget.
     */
    public function cap(string $type, array $payload): ?array
    {
        if (self::encodedBytes($payload) <= self::MAX_ITEM_BYTES) {
            return $payload;
        }

        foreach ($payload as $key => $value) {
            if (is_string($value) && mb_strlen($value, '8bit') > self::MAX_ITEM_FIELD_BYTES) {
                $payload[$key] = mb_strcut($value, 0, self::MAX_ITEM_FIELD_BYTES).self::TRUNCATION_SUFFIX;

                continue;
            }

            if (is_array($value)) {
                $payload[$key] = PayloadSizer::capBytes($value, self::MAX_ITEM_FIELD_BYTES, self::FIELD_TRUNCATION_REASON);
            }
        }

        if (self::encodedBytes($payload) > self::MAX_ITEM_BYTES) {
            $this->log->warning('Captured item exceeded the per-item byte budget and was dropped', [
                'type' => $type,
                'max_bytes' => self::MAX_ITEM_BYTES,
            ]);

            return null;
        }

        $this->log->warning('Captured item exceeded the per-item byte budget and was shrunk', [
            'type' => $type,
            'max_bytes' => self::MAX_ITEM_BYTES,
        ]);

        return $payload;
    }

    /**
     * Byte size, measured with `mb_strlen(..., '8bit')` (NOT `strlen`: the
     * repo's Pint `mb_str_functions` rule would rewrite `strlen` to a
     * char-counting `mb_strlen`, breaking the budget on multibyte data).
     *
     * @param  array<string, mixed>  $payload
     */
    private static function encodedBytes(array $payload): int
    {
        return mb_strlen((string) json_encode($payload), '8bit');
    }
}
