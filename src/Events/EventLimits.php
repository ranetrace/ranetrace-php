<?php

declare(strict_types=1);

namespace Ranetrace\Php\Events;

use Ranetrace\Php\Support\Diagnostics;
use Ranetrace\Php\Support\ItemByteBudget;
use Ranetrace\Php\Support\PayloadSizer;
use Throwable;

/**
 * Holds one event item to the two size limits of the events endpoint, so the
 * event arrives cut rather than being refused.
 *
 * The endpoint refuses an event whose JSON is over {@see MAX_ITEM_BYTES} and
 * one with a top-level string property over {@see MAX_PROPERTY_VALUE_BYTES}.
 * A refused event is counted `failed`, which is final, and the API's answer
 * names only a count, so the SDK is the one place that can still say which
 * event it was. Both SDKs run every event through {@see fit()} right after
 * {@see EventItemBuilder::build()}: this package in {@see EventTracker}, the
 * Laravel SDK before it queues the capture job, so the queued payload is
 * already small. It is a class of its own rather than a step inside the
 * builder because it needs a diagnostics sink the builder does not take, and
 * a Laravel SDK release that builds events with an older constructor keeps
 * working when this package is updated under it.
 *
 * It runs before {@see ItemByteBudget}, whose budget is far larger, so the
 * general budget has nothing left to do for an event.
 *
 * Largest first, so an event keeps as many of its properties as possible: a
 * sale with a long products list keeps its order id, total, currency and
 * product count and loses the list. A replaced value becomes the nested
 * `_truncated` marker {@see PayloadSizer::capBytes()} uses, which
 * `contract/envelope.json` allows inside a free-shape field. A value no
 * larger than that marker is never replaced, since that would grow the item.
 */
final class EventLimits
{
    /**
     * The endpoint's limit on the JSON encoding of the whole item, as its
     * `additional_checks.max_item_bytes` in `contract/items/events.json`
     * states it. The contract suite holds the two equal.
     */
    public const int MAX_ITEM_BYTES = 5_120;

    /**
     * The endpoint's limit on a top-level string property, as its
     * `additional_checks.max_property_value_chars` states it. The deployed
     * backend counts it in bytes and a newer one in characters. A string of at
     * most 500 bytes is at most 500 characters, so a cut in bytes passes
     * either one.
     */
    public const int MAX_PROPERTY_VALUE_BYTES = 500;

    public const string PROPERTY_REPLACED_REASON = 'Property exceeded the events endpoint size limit and was removed';

    public const string PROPERTIES_REPLACED_REASON = 'Properties exceeded the events endpoint size limit and were removed';

    /**
     * The suffix {@see ItemByteBudget} puts on a cut string, counted inside
     * the limit here.
     */
    private const string TRUNCATION_SUFFIX = '... (truncated)';

    public function __construct(private readonly Diagnostics $log) {}

    /**
     * The item as it may be sent, or null when it cannot be brought within the
     * limits. An item within both limits is returned untouched and logs
     * nothing. Each cut writes one warning, and so does a drop.
     *
     * Never throws: a failure inside costs the cut, and the item goes on to
     * the general budget as it was built.
     *
     * @param  array<string, mixed>  $item  The eight-key item {@see EventItemBuilder::build()} made.
     * @return array<string, mixed>|null
     */
    public function fit(array $item): ?array
    {
        try {
            return $this->cut($item);
        } catch (Throwable $failure) {
            $this->warn('Event could not be held to the events endpoint limits', [
                'event_name' => $item['event_name'] ?? null,
                'exception' => $failure->getMessage(),
            ]);

            return $item;
        }
    }

    /**
     * The byte length of PHP's default JSON encoding, which is how the
     * endpoint measures: it decodes the batch and encodes each item again, so
     * escaped slashes and `\uXXXX` count. Measured with `mb_strlen(..., '8bit')`
     * rather than `strlen`, which the repo's Pint `mb_str_functions` rule
     * would rewrite to a character count. Null when the value cannot be
     * encoded at all.
     */
    private static function encodedBytes(mixed $value): ?int
    {
        $encoded = json_encode($value);

        return $encoded === false ? null : mb_strlen($encoded, '8bit');
    }

    /**
     * @param  array<string, mixed>  $item
     * @return array<string, mixed>|null
     */
    private function cut(array $item): ?array
    {
        $original = $item;
        $cutProperties = [];

        if (is_array($item['properties'] ?? null)) {
            [$item['properties'], $cutProperties] = $this->cutLongStrings($item['properties']);
        }

        [$item, $replacedProperties] = $this->replaceLargestProperties($item);
        $allPropertiesReplaced = false;
        $bytes = self::encodedBytes($item);

        if (($bytes === null || $bytes > self::MAX_ITEM_BYTES) && $this->replaceable($item)) {
            $item['properties'] = ['_truncated' => self::PROPERTIES_REPLACED_REASON];
            $allPropertiesReplaced = true;
            $bytes = self::encodedBytes($item);
        }

        if ($bytes === null || $bytes > self::MAX_ITEM_BYTES) {
            $this->warn('Event exceeded the events endpoint limits and was dropped', [
                'event_name' => $item['event_name'] ?? null,
                'max_item_bytes' => self::MAX_ITEM_BYTES,
            ]);

            return null;
        }

        if ($cutProperties === [] && $replacedProperties === [] && ! $allPropertiesReplaced) {
            return $original;
        }

        $this->warn('Event exceeded the events endpoint limits and was cut', $this->cutContext(
            $item['event_name'] ?? null,
            $allPropertiesReplaced ? [] : array_values(array_diff($cutProperties, $replacedProperties)),
            $replacedProperties,
            $allPropertiesReplaced,
        ));

        return $item;
    }

    /**
     * Cut every top-level string property longer than the property limit, on
     * a character boundary, so the result with its suffix fits the limit.
     *
     * @param  array<array-key, mixed>  $properties
     * @return array{0: array<array-key, mixed>, 1: list<array-key>}
     */
    private function cutLongStrings(array $properties): array
    {
        $cut = [];

        foreach ($properties as $key => $value) {
            if (is_string($value) && mb_strlen($value, '8bit') > self::MAX_PROPERTY_VALUE_BYTES) {
                $properties[$key] = mb_strcut($value, 0, self::MAX_PROPERTY_VALUE_BYTES - mb_strlen(self::TRUNCATION_SUFFIX, '8bit'), 'UTF-8').self::TRUNCATION_SUFFIX;
                $cut[] = $key;
            }
        }

        return [$properties, $cut];
    }

    /**
     * Replace top-level property values with the marker, largest first, until
     * the item fits.
     *
     * Each value is measured once. A top-level value's encoding is a verbatim
     * part of the item's encoding, so the item's size after a replacement is
     * worked out rather than encoded again; an event with thousands of large
     * properties would otherwise be encoded thousands of times. A value JSON
     * cannot encode counts as the largest, since it is over every limit, and
     * while the item cannot be encoded it is encoded again after each such
     * replacement. Once only encodable values are left and the item still
     * cannot be encoded, replacing them cannot help, so the pass stops.
     *
     * @param  array<string, mixed>  $item
     * @return array{0: array<string, mixed>, 1: list<array-key>}
     */
    private function replaceLargestProperties(array $item): array
    {
        $properties = $item['properties'] ?? null;
        $bytes = self::encodedBytes($item);

        if (! is_array($properties) || ($bytes !== null && $bytes <= self::MAX_ITEM_BYTES)) {
            return [$item, []];
        }

        $marker = ['_truncated' => self::PROPERTY_REPLACED_REASON];
        $markerBytes = (int) self::encodedBytes($marker);
        $sizes = [];

        foreach ($properties as $key => $value) {
            $sizes[$key] = self::encodedBytes($value) ?? PHP_INT_MAX;
        }

        arsort($sizes);
        $replaced = [];

        foreach ($sizes as $key => $size) {
            if ($bytes !== null && $bytes <= self::MAX_ITEM_BYTES) {
                break;
            }

            if ($size <= $markerBytes || ($bytes === null && $size !== PHP_INT_MAX)) {
                break;
            }

            $properties[$key] = $marker;
            $replaced[] = $key;
            $item['properties'] = $properties;
            $bytes = $bytes === null ? self::encodedBytes($item) : $bytes - $size + $markerBytes;
        }

        return [$item, $replaced];
    }

    /**
     * Whether the item has a `properties` value larger than the marker that
     * would replace it. An item without the key is never given one.
     *
     * @param  array<string, mixed>  $item
     */
    private function replaceable(array $item): bool
    {
        if (! array_key_exists('properties', $item)) {
            return false;
        }

        $bytes = self::encodedBytes($item['properties']) ?? PHP_INT_MAX;

        return $bytes > (int) self::encodedBytes(['_truncated' => self::PROPERTIES_REPLACED_REASON]);
    }

    /**
     * @param  list<array-key>  $cutProperties
     * @param  list<array-key>  $replacedProperties
     * @return array<string, mixed>
     */
    private function cutContext(mixed $eventName, array $cutProperties, array $replacedProperties, bool $allPropertiesReplaced): array
    {
        $context = ['event_name' => $eventName];

        if ($cutProperties !== []) {
            $context['cut_properties'] = $cutProperties;
            $context['max_property_value_bytes'] = self::MAX_PROPERTY_VALUE_BYTES;
        }

        if ($allPropertiesReplaced) {
            $context['all_properties_replaced'] = true;
        } elseif ($replacedProperties !== []) {
            $context['replaced_properties'] = $replacedProperties;
        }

        if ($allPropertiesReplaced || $replacedProperties !== []) {
            $context['max_item_bytes'] = self::MAX_ITEM_BYTES;
        }

        return $context;
    }

    /**
     * Write one warning, swallowing a sink that fails: the cut is already
     * made, and a lost log line must not cost the event.
     *
     * @param  array<string, mixed>  $context
     */
    private function warn(string $message, array $context): void
    {
        try {
            $this->log->warning($message, $context);
        } catch (Throwable) {
            // The diagnostics sink is the only place left to report to.
        }
    }
}
