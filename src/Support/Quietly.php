<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use Throwable;

/**
 * Runs a filesystem call with PHP's error reporting muted.
 *
 * The `@` operator is not enough: it still invokes whatever error handler the
 * host installed, and an unwritable buffer directory would then surface as a
 * warning in the host's logs. Worse, a host that routes its logs back into
 * Ranetrace would capture that warning, buffer it, and fail to write it for the
 * same reason. Every failure in the spool is expected and handled by a return
 * value instead.
 *
 * `Support\InternalLogger` deliberately keeps its own copy of this and does not
 * catch `Throwable`: it needs a sink failure to reach its own stderr fallback,
 * where the callers here want a plain `false`.
 */
final class Quietly
{
    /**
     * @param  callable(): mixed  $callback
     * @return mixed The callback's return value, or false when it threw.
     */
    public static function call(callable $callback): mixed
    {
        set_error_handler(static fn (): bool => true);

        try {
            return $callback();
        } catch (Throwable) {
            return false;
        } finally {
            restore_error_handler();
        }
    }
}
