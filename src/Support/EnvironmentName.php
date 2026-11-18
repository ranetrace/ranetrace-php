<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use Throwable;

/**
 * The configured environment name as every item builder sends it, so one
 * application never reports two spellings of its environment.
 *
 * The errors and JavaScript errors endpoints take an `environment` of at most
 * {@see MAX_LENGTH} characters and refuse the whole item past it, which is
 * final. A longer name is therefore cut to its first {@see MAX_LENGTH}
 * characters, counted as the endpoint counts them, with no suffix: it is a
 * name, and a dashboard filters on it. The log item's `extra.environment` has
 * no limit at the endpoint and carries the same cut name, so a log record and
 * an error from one deployment name it alike.
 *
 * A name that long is cut and not refused as a configuration error: monitoring
 * must not stop over a name. The cost is that two names alike in their first
 * {@see MAX_LENGTH} characters arrive as one environment, which is why an
 * error item's cut is written to the internal log. The JavaScript error and log
 * builders have no diagnostics sink, so their cut is silent.
 */
final class EnvironmentName
{
    /** The longest environment name the errors and JavaScript errors endpoints take. */
    public const int MAX_LENGTH = 50;

    /**
     * The name sent for a configured value that is not a scalar, the same name
     * the configuration falls back to when the host sets none.
     */
    public const string FALLBACK = 'production';

    /**
     * The name as sent: a scalar cast to a string, made valid UTF-8 by
     * {@see Utf8::repair()}, then cut to {@see MAX_LENGTH} characters. Any
     * other value, a missing one included, is sent as {@see FALLBACK}.
     *
     * With `$log`, a name that had to be cut writes one warning naming the
     * configured name, the name as sent and the limit. A sink that fails costs
     * the warning, never the item.
     */
    public static function fromConfig(mixed $configured, ?Diagnostics $log = null): string
    {
        if (! is_scalar($configured)) {
            return self::FALLBACK;
        }

        $name = Utf8::repair((string) $configured);

        if (mb_strlen($name) <= self::MAX_LENGTH) {
            return $name;
        }

        $sent = mb_substr($name, 0, self::MAX_LENGTH);

        try {
            $log?->warning('Ranetrace environment name exceeded the endpoint limit and was cut', [
                'configured_environment' => $name,
                'sent_environment' => $sent,
                'max_length' => self::MAX_LENGTH,
            ]);
        } catch (Throwable) {
            // The diagnostics sink is the only place left to report to.
        }

        return $sent;
    }
}
