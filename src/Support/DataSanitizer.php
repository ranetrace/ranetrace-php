<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use Closure;
use Throwable;

/**
 * Flattens arbitrary user data into something JSON can carry: closures,
 * resources and objects become descriptive strings or their array form.
 *
 * Ported verbatim from `ranetrace/ranetrace-laravel`
 * (`src/Utilities/DataSanitizer.php`). The markers it emits (`[Closure]`,
 * `[Resource: …]`, `[Object: …]`, `[Max depth exceeded]`) show up in captured
 * payloads, so their wording and the depth ceiling must not drift between the
 * two SDKs. Pure static, no configuration.
 */
final class DataSanitizer
{
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
            return '[Max depth exceeded]';
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

        // Return primitive values as-is.
        return $data;
    }
}
