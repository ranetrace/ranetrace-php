<?php

declare(strict_types=1);

namespace Ranetrace\Php\Tests\Contract;

/**
 * Checks a fixture example against the field descriptors in the same fixture.
 *
 * This lives in the test suite rather than in `src/` on purpose. It answers one
 * question, "is this artifact internally consistent", and nothing on a capture
 * or transport path ever asks it. Shipping it would put a second validator in
 * the package's public surface that the package itself never calls, and the
 * first time it disagreed with the backend's Laravel validator, someone would
 * have to decide which one was the contract. The JSON fixtures are the contract;
 * this is a lint over them.
 *
 * The vocabulary it understands is the one the fixtures use: `required`, `type`
 * (string, integer, number, boolean, array, date), `max`, `min`, `size`, `enum`
 * and `pattern`, with Laravel dot syntax (including `*` wildcards) for nested
 * rules. `max`, `min` and `size` follow Laravel's sizing rules: a number is
 * compared by value, an array by count, a string by character length.
 */
final class DescriptorValidator
{
    /**
     * Every way an example breaks its own spec, as human-readable strings. An
     * empty list means the example is valid.
     *
     * @param  array<string, mixed>  $fields  The fixture's `fields` map.
     * @param  array<string, mixed>  $item  The example item.
     * @param  bool  $strictFields  Whether a key outside the spec rejects the item.
     * @param  list<string>  $legacyFields  Extra top-level keys the endpoint still tolerates.
     * @return list<string>
     */
    public static function violations(array $fields, array $item, bool $strictFields = false, array $legacyFields = []): array
    {
        $violations = [];

        if ($strictFields) {
            $allowed = array_merge(self::topLevelKeys($fields), $legacyFields);

            foreach (array_keys($item) as $key) {
                if (! in_array((string) $key, $allowed, true)) {
                    $violations[] = "unexpected field '{$key}' (the endpoint allow-lists its field set)";
                }
            }
        }

        foreach ($fields as $rule => $descriptor) {
            if (! is_array($descriptor)) {
                continue;
            }

            foreach (self::resolve($item, explode('.', (string) $rule), '') as $resolved) {
                $violations = array_merge($violations, self::check($descriptor, $resolved));
            }
        }

        return $violations;
    }

    /**
     * The rule keys that name a top-level field, so nested and wildcard rules do
     * not widen the allow-list.
     *
     * @param  array<string, mixed>  $fields
     * @return list<string>
     */
    public static function topLevelKeys(array $fields): array
    {
        $keys = [];

        foreach (array_keys($fields) as $rule) {
            if (! str_contains((string) $rule, '.')) {
                $keys[] = (string) $rule;
            }
        }

        return $keys;
    }

    /**
     * Walk one dot rule into the example, yielding every position it names.
     *
     * A rule only ever judges its own leaf. An absent, null or non-traversable
     * ancestor yields nothing rather than a violation, which is what Laravel
     * does too: `breadcrumbs.*.timestamp` is required for every breadcrumb that
     * is there, and says nothing at all when `breadcrumbs` is absent. The
     * ancestor's own descriptor is what judges the ancestor.
     *
     * @param  list<string>  $segments
     * @return list<array{path: string, exists: bool, value: mixed}>
     */
    private static function resolve(mixed $value, array $segments, string $path): array
    {
        if ($segments === []) {
            return [['path' => $path, 'exists' => true, 'value' => $value]];
        }

        if (! is_array($value)) {
            return [];
        }

        $segment = array_shift($segments);

        if ($segment === '*') {
            $resolved = [];

            foreach ($value as $key => $child) {
                $resolved = array_merge($resolved, self::resolve($child, $segments, self::join($path, (string) $key)));
            }

            return $resolved;
        }

        $childPath = self::join($path, $segment);

        if (! array_key_exists($segment, $value)) {
            return $segments === [] ? [['path' => $childPath, 'exists' => false, 'value' => null]] : [];
        }

        return self::resolve($value[$segment], $segments, $childPath);
    }

    private static function join(string $path, string $segment): string
    {
        return $path === '' ? $segment : $path.'.'.$segment;
    }

    /**
     * @param  array<string, mixed>  $descriptor
     * @param  array{path: string, exists: bool, value: mixed}  $resolved
     * @return list<string>
     */
    private static function check(array $descriptor, array $resolved): array
    {
        $path = $resolved['path'];
        $required = ($descriptor['required'] ?? false) === true;

        if (! $resolved['exists'] || $resolved['value'] === null) {
            return $required ? ["'{$path}' is required and must not be null"] : [];
        }

        $value = $resolved['value'];
        $violations = [];

        $type = isset($descriptor['type']) && is_string($descriptor['type']) ? $descriptor['type'] : null;

        if ($type !== null && ! self::matchesType($value, $type)) {
            return ["'{$path}' must be of type {$type}, got ".get_debug_type($value)];
        }

        [$size, $unit] = self::measure($value, $type);

        foreach (['max', 'min', 'size'] as $bound) {
            if (! isset($descriptor[$bound]) || ! is_numeric($descriptor[$bound])) {
                continue;
            }

            $limit = (float) $descriptor[$bound];

            $broken = match ($bound) {
                'max' => $size > $limit,
                'min' => $size < $limit,
                default => $size !== $limit,
            };

            if ($broken) {
                $violations[] = "'{$path}' breaks {$bound} {$descriptor[$bound]}: {$size} {$unit}";
            }
        }

        if (isset($descriptor['enum']) && is_array($descriptor['enum']) && ! in_array($value, $descriptor['enum'], true)) {
            $violations[] = "'{$path}' is not one of ".implode(', ', array_map(strval(...), $descriptor['enum']));
        }

        if (isset($descriptor['pattern']) && is_string($descriptor['pattern']) && is_string($value)
            && preg_match($descriptor['pattern'], $value) !== 1) {
            $violations[] = "'{$path}' does not match {$descriptor['pattern']}";
        }

        return $violations;
    }

    private static function matchesType(mixed $value, string $type): bool
    {
        return match ($type) {
            'string' => is_string($value),
            'integer' => is_int($value),
            'number' => is_int($value) || is_float($value),
            'boolean' => is_bool($value),
            'array' => is_array($value),
            'date' => is_string($value) && strtotime($value) !== false,
            default => true,
        };
    }

    /**
     * The number Laravel's max/min/size rules compare against, and what it
     * counts, for the failure message.
     *
     * @return array{0: float, 1: string}
     */
    private static function measure(mixed $value, ?string $type): array
    {
        if ($type === 'integer' || $type === 'number' || (($type === null || $type === 'date') && (is_int($value) || is_float($value)))) {
            return [is_numeric($value) ? (float) $value : 0.0, 'value'];
        }

        if (is_array($value)) {
            return [(float) count($value), 'items'];
        }

        return [(float) mb_strlen(is_scalar($value) ? (string) $value : ''), 'characters'];
    }
}
