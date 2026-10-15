<?php

declare(strict_types=1);

namespace Ranetrace\Php\Errors;

/**
 * Which frames of a list survive a cap: the innermost and the outermost, with
 * the middle dropped.
 *
 * Four fifths of the kept frames come from the innermost end and one fifth from
 * the outermost, so 50 kept frames are the 40 innermost and the 10 outermost.
 * The innermost end is where the error happened and where the application's
 * own code usually sits, so it gets the larger share; the outermost end names
 * the entry point (the script, the console command, the kernel) and needs only
 * a few frames to do it. Deep recursion keeps both ends of the loop this way.
 *
 * {@see PayloadBuilder} caps with it and {@see ErrorItemShedder} shrinks a list
 * further with it, so a shrunk list keeps the same shape as a capped one.
 */
final class FrameCap
{
    /**
     * Frames per list, a wire contract bound.
     */
    public const int MAX_FRAMES = 50;

    /**
     * The 0-based positions to keep, in order, out of a list of $count frames
     * when at most $keep may stay.
     *
     * @return list<int>
     */
    public static function positions(int $count, int $keep): array
    {
        $keep = max(0, min($count, $keep));

        if ($keep === $count) {
            return $count === 0 ? [] : range(0, $count - 1);
        }

        $outermost = intdiv($keep, 5);
        $innermost = $keep - $outermost;

        return [
            ...($innermost === 0 ? [] : range(0, $innermost - 1)),
            ...($outermost === 0 ? [] : range($count - $outermost, $count - 1)),
        ];
    }
}
