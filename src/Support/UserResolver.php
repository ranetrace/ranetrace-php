<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use Ranetrace\Php\Config;
use Throwable;

/**
 * Asks the host's `user_resolver` who the current user is, for every item that
 * carries a user: errors, events and browser errors.
 *
 * The resolver is host code, often a session store or an auth guard, and it is
 * called from inside a capture path, so it can throw at the moment the host is
 * already in trouble. A throw is contained here: it costs the item its user and
 * leaves one warning in the internal log, and the item is still captured.
 *
 * What the resolver returned is handed back unchecked. Each item builder shapes
 * it to the fields its endpoint takes, because those differ: an error keeps the
 * id and the email, an event and a browser error keep the id only.
 */
final class UserResolver
{
    /**
     * What the configured resolver returned, or null when none is configured or it threw.
     */
    public static function resolve(Config $config, Diagnostics $log): mixed
    {
        $resolver = $config->get('user_resolver');

        if (! is_callable($resolver)) {
            return null;
        }

        try {
            return $resolver();
        } catch (Throwable $failure) {
            $log->warning('Ranetrace user resolver failed', [
                'exception' => $failure->getMessage(),
            ]);

            return null;
        }
    }
}
