<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use Closure;
use Throwable;

/**
 * Flattens arbitrary user data into something JSON can carry: closures,
 * resources and objects become descriptive strings or their array form, and a
 * float JSON has no spelling for (INF, -INF, NAN) becomes the string PHP spells
 * it as, `"INF"`, `"-INF"` or `"NAN"`.
 *
 * `json_encode` refuses the whole value when one float in it is not finite, so
 * a single ratio divided by zero in a log context or an event property would
 * otherwise cost its item, or in a host whose buffer does not encode, the batch
 * it is sent in. Every shared item builder runs its free-shape fields through
 * here, and only those: a field whose wire type is a number never does, because
 * a string there would refuse the item.
 *
 * Shared with `ranetrace/ranetrace-laravel`, which reaches it through the
 * shared item builders and keeps no copy of its own. The markers it emits
 * (`[Closure]`, `[Resource: …]`, `[Object: …]`, `[Max depth exceeded]`) show up
 * in captured payloads, so their wording and the depth ceiling are part of what
 * both SDKs send. Pure static, no configuration.
 */
final class DataSanitizer
{
    /**
     * What a value past a depth ceiling becomes. Public so a caller with a
     * tighter ceiling of its own marks the cut in the same words.
     */
    public const string MAX_DEPTH_MARKER = '[Max depth exceeded]';

    /**
     * Hard recursion ceiling. Bounds deep or circular object/array graphs so a
     * pathological structure cannot recurse to stack exhaustion, which would be
     * an uncatchable fatal, defeating the capture paths' failure isolation.
     */
    private const int MAX_DEPTH = 20;

    /**
     * Sanitize data for serialization by removing closures and non-serializable
     * values.
     */
    public static function sanitizeForSerialization(mixed $data, int $depth = 0): mixed
    {
        if ($depth >= self::MAX_DEPTH) {
            return self::MAX_DEPTH_MARKER;
        }

        if (is_array($data)) {
            return array_map(
                static fn (mixed $value): mixed => self::sanitizeForSerialization($value, $depth + 1),
                $data
            );
        }

        if (is_object($data)) {
            if ($data instanceof Closure) {
                return '[Closure]';
            }

            // Try to convert objects to arrays, but catch any serialization issues.
            try {
                // For objects that implement JsonSerializable.
                if (method_exists($data, 'jsonSerialize')) {
                    return self::sanitizeForSerialization($data->jsonSerialize(), $depth + 1);
                }

                // For objects that implement toArray.
                if (method_exists($data, 'toArray')) {
                    return self::sanitizeForSerialization($data->toArray(), $depth + 1);
                }

                // For other objects, try to convert to string or return class name.
                if (method_exists($data, '__toString')) {
                    return (string) $data;
                }

                return '[Object: '.$data::class.']';
            } catch (Throwable) {
                return '[Object: '.$data::class.' - serialization failed]';
            }
        }

        // For resources and other non-serializable types.
        if (is_resource($data)) {
            return '[Resource: '.get_resource_type($data).']';
        }

        if (is_float($data) && ! is_finite($data)) {
            return self::spellNonFinite($data);
        }

        // Return primitive values as-is.
        return $data;
    }

    /**
     * Spelled out rather than cast: PHP 8.5 warns when NAN is cast to a string,
     * and a host that turns warnings into exceptions would lose the item to it.
     */
    private static function spellNonFinite(float $value): string
    {
        if (is_nan($value)) {
            return 'NAN';
        }

        return $value > 0 ? 'INF' : '-INF';
    }
}
