<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * The SDK's diagnostics sink, as the shared builders see it.
 *
 * {@see InternalLogger} is this package's implementation, writing to its own
 * daily file. The interface exists so a framework adapter can hand the shared
 * builders ITS diagnostics sink instead: the Laravel SDK writes to a dedicated
 * `ranetrace_internal` log channel, and a builder it shares with this package
 * must keep reporting there rather than into a temp-directory file the operator
 * never looks at.
 *
 * The isolation rule travels with the interface: whatever implements it must
 * never route back into the host's own capture path. A failing send that logged
 * through a logger the host had pointed at Ranetrace would be captured,
 * buffered and sent, and fail again.
 */
interface Diagnostics
{
    /**
     * @param  array<string, mixed>  $context
     */
    public function debug(string $message, array $context = []): void;

    /**
     * @param  array<string, mixed>  $context
     */
    public function info(string $message, array $context = []): void;

    /**
     * @param  array<string, mixed>  $context
     */
    public function notice(string $message, array $context = []): void;

    /**
     * @param  array<string, mixed>  $context
     */
    public function warning(string $message, array $context = []): void;

    /**
     * @param  array<string, mixed>  $context
     */
    public function error(string $message, array $context = []): void;

    /**
     * @param  array<string, mixed>  $context
     */
    public function critical(string $message, array $context = []): void;
}
