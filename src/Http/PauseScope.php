<?php

declare(strict_types=1);

namespace Ranetrace\Php\Http;

/**
 * How wide a pause a batch response calls for.
 *
 * The values are the spellings `contract/responses.json` uses, so a conformance
 * test can compare a decision against the fixture without a translation table.
 * `Everything` is the contract's `global`, spelled out because `global` is a
 * PHP keyword and a case named after it reads like the statement.
 */
enum PauseScope: string
{
    case None = 'none';

    case Feature = 'feature';

    case Everything = 'global';
}
