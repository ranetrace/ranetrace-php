<?php

declare(strict_types=1);

namespace Ranetrace\Php\Errors;

/**
 * Maps a stack frame's location to the file a developer actually wrote.
 *
 * A framework that runs generated code, such as compiled Blade views, hands
 * {@see PayloadBuilder} one of these so a frame in the generated file arrives as
 * the template and the template line, with the template's source. The mapping
 * runs before the path is made relative, before the vendor check and before the
 * source is read, so all three describe the mapped location.
 *
 * It is applied to every frame and to each previous exception's throw site. The
 * item's own `file`, `line` and `context` are not mapped (see
 * {@see PayloadBuilder::build()}).
 *
 * A mapper is host code called from inside the capture path: one that throws
 * costs that one mapping, which falls back to the unmapped location, and never
 * the error report.
 */
interface FrameMapper
{
    /**
     * The mapped location, or null when this location is not one this mapper
     * knows. Both locations carry absolute paths.
     */
    public function map(FrameLocation $location): ?FrameLocation;
}
