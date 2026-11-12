<?php

declare(strict_types=1);

namespace Ranetrace\Php\Worker;

/**
 * What happened to one type's test item. {@see TestRun} decides it,
 * {@see TestReport} words it.
 */
enum TestOutcome
{
    /** A 200 that counted the item as processed. */
    case Accepted;

    /** A 200 that counted the item as ignored. */
    case AcceptedNotStored;

    /** A 200 that counted the item as failed: the API refused it. */
    case Refused;

    /** A 200 that counted the item as unprocessed: the API ran out of time. */
    case NotProcessed;

    /** A 200 that counted nothing, or whose body was not JSON. */
    case Unrecognised;

    case Unauthorized;

    case Forbidden;

    case RateLimited;

    /** No HTTP status was reached. */
    case Unreachable;

    /** Any other status. */
    case Failed;

    /** An earlier type met a 401, so this one was not sent. */
    case NotSent;

    /** The type's own feature flag is off. */
    case Skipped;

    /** The capture path left no item to send. */
    case NotCaptured;

    /**
     * Whether the API took the item: it answered 200 and counted it as
     * processed, or as ignored, which it does on purpose.
     */
    public function accepted(): bool
    {
        return $this === self::Accepted || $this === self::AcceptedNotStored;
    }
}
