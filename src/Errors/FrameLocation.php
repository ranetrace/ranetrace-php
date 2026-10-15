<?php

declare(strict_types=1);

namespace Ranetrace\Php\Errors;

/**
 * A place in a source file: an absolute path and a 1-based line, before any
 * path is made relative to the project root.
 *
 * It is what a {@see FrameMapper} is handed and what it hands back.
 */
final readonly class FrameLocation
{
    public function __construct(
        public string $file,
        public int $line,
    ) {}
}
