<?php

declare(strict_types=1);

namespace Ranetrace\Php\Errors;

/**
 * Brings an over-budget error item under the byte budget by shedding what its
 * structured frames carry, before the generic per-field cut runs.
 *
 * The generic cut ({@see \Ranetrace\Php\Support\ItemByteBudget::cap()})
 * replaces every array field over 8 KB with a `_truncated` marker. Inside
 * `frames` or `previous` the backend refuses that marker, which would cost the
 * whole report, so an error item sheds here first, in this order, stopping as
 * soon as the item fits:
 *
 * 1. `source` objects. The previous exceptions' frames go first, the farthest
 *    exception first, each list from its outermost frame inward; then the
 *    item's own frames, outermost first. The item's first app frame (its
 *    innermost frame with a source) and the previous exceptions' throw sites
 *    go last, in that order: they are the lines a reader looks at first.
 * 2. Frames, by growing the dropped middle of each list with {@see FrameCap},
 *    so a shrunk list keeps the shape of a capped one and `frames_omitted`
 *    counts every frame gone. The previous exceptions' lists shrink first, the
 *    farthest first, then the item's own, down to an empty list if need be.
 * 3. Previous exceptions, from the far end; `previous` becomes null when none
 *    is left.
 *
 * So the frames are never the reason an item is dropped: shed in full they are
 * an empty list and a null `previous`, a few bytes. An item still over budget
 * after that is over because of its other fields, and the generic cut handles
 * those.
 *
 * Sizes are tracked by subtraction from one encode of the item, since a nested
 * value encodes to the same bytes inside the item as on its own, and confirmed
 * with a fresh encode whenever the running total says the item fits. Encoding
 * uses `JSON_PARTIAL_OUTPUT_ON_ERROR`, so an unencodable field elsewhere in
 * the item cannot stop the frames from being measured.
 *
 * Public and static so `ranetrace/ranetrace-laravel`, which holds items to the
 * same budget in its own job class, sheds with the same order.
 */
final class ErrorItemShedder
{
    /**
     * @param  array<string, mixed>  $item
     * @return array<string, mixed>
     */
    public static function shed(array $item, int $maxBytes): array
    {
        $bytes = self::bytes($item);

        if ($bytes <= $maxBytes) {
            return $item;
        }

        foreach (self::sourcePaths($item) as $path) {
            $source = self::get($item, $path);

            if ($source === null) {
                continue;
            }

            $item = self::set($item, $path, null);
            $bytes -= self::bytes($source) - 4;

            if ($bytes <= $maxBytes && ($bytes = self::bytes($item)) <= $maxBytes) {
                return $item;
            }
        }

        foreach (self::frameListPaths($item) as $path) {
            while (is_array($frames = self::get($item, [...$path, 'frames'])) && $frames !== []) {
                $frames = array_values($frames);
                $kept = FrameCap::positions(count($frames), count($frames) - 1);
                $removed = array_values(array_diff(array_keys($frames), $kept))[0];

                $omitted = self::get($item, [...$path, 'frames_omitted']);
                $item = self::set($item, [...$path, 'frames'], array_map(static fn (int $position): mixed => $frames[$position], $kept));
                $item = self::set($item, [...$path, 'frames_omitted'], (is_int($omitted) ? $omitted : 0) + 1);
                $bytes -= self::bytes($frames[$removed]) + (count($frames) > 1 ? 1 : 0);

                if ($bytes <= $maxBytes && ($bytes = self::bytes($item)) <= $maxBytes) {
                    return $item;
                }
            }
        }

        while (is_array($item['previous'] ?? null) && $item['previous'] !== []) {
            $previous = array_values($item['previous']);
            $dropped = array_pop($previous);
            $item['previous'] = $previous === [] ? null : $previous;
            $bytes -= self::bytes($dropped) + 1;

            if ($bytes <= $maxBytes && ($bytes = self::bytes($item)) <= $maxBytes) {
                return $item;
            }
        }

        return $item;
    }

    /**
     * Every source position in shedding order.
     *
     * @param  array<string, mixed>  $item
     * @return list<list<int|string>>
     */
    private static function sourcePaths(array $item): array
    {
        $previous = self::previousPositions($item);
        $paths = [];

        foreach ($previous as $position) {
            foreach (self::outermostFirst($item['previous'][$position]['frames'] ?? null) as $frame) {
                $paths[] = ['previous', $position, 'frames', $frame, 'source'];
            }
        }

        $own = self::outermostFirst($item['frames'] ?? null);
        $firstAppFrame = null;

        foreach (array_reverse($own) as $frame) {
            if (($item['frames'][$frame]['source'] ?? null) !== null) {
                $firstAppFrame = $frame;

                break;
            }
        }

        foreach ($own as $frame) {
            if ($frame !== $firstAppFrame) {
                $paths[] = ['frames', $frame, 'source'];
            }
        }

        if ($firstAppFrame !== null) {
            $paths[] = ['frames', $firstAppFrame, 'source'];
        }

        foreach ($previous as $position) {
            $paths[] = ['previous', $position, 'source'];
        }

        return $paths;
    }

    /**
     * The owners of every frame list in shrinking order: the previous
     * exceptions, farthest first, then the item itself.
     *
     * @param  array<string, mixed>  $item
     * @return list<list<int|string>>
     */
    private static function frameListPaths(array $item): array
    {
        return [
            ...array_map(static fn (int|string $position): array => ['previous', $position], self::previousPositions($item)),
            [],
        ];
    }

    /**
     * The keys of `previous`, farthest exception first.
     *
     * @param  array<string, mixed>  $item
     * @return list<int|string>
     */
    private static function previousPositions(array $item): array
    {
        $previous = $item['previous'] ?? null;

        return is_array($previous) ? array_reverse(array_keys($previous)) : [];
    }

    /**
     * The keys of a frame list, outermost frame first.
     *
     * @return list<int|string>
     */
    private static function outermostFirst(mixed $frames): array
    {
        return is_array($frames) ? array_reverse(array_keys($frames)) : [];
    }

    /**
     * @param  array<string, mixed>  $item
     * @param  list<int|string>  $path
     */
    private static function get(array $item, array $path): mixed
    {
        $value = $item;

        foreach ($path as $segment) {
            if (! is_array($value) || ! array_key_exists($segment, $value)) {
                return null;
            }

            $value = $value[$segment];
        }

        return $value;
    }

    /**
     * @param  array<array-key, mixed>  $item
     * @param  list<int|string>  $path
     * @return array<array-key, mixed>
     */
    private static function set(array $item, array $path, mixed $value): array
    {
        if ($path === []) {
            return is_array($value) ? $value : $item;
        }

        $segment = array_shift($path);

        $item[$segment] = $path === []
            ? $value
            : self::set(is_array($item[$segment] ?? null) ? $item[$segment] : [], $path, $value);

        return $item;
    }

    private static function bytes(mixed $value): int
    {
        return mb_strlen((string) json_encode($value, JSON_PARTIAL_OUTPUT_ON_ERROR), '8bit');
    }
}
