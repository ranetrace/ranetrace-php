<?php

declare(strict_types=1);

/**
 * The exception `vendor/bin/ranetrace-test` and `Ranetrace::sendTest()` send.
 *
 * It is made here, outside `src/`, because `Errors\ErrorReporter` drops every
 * throwable whose file is under `src/` as one the SDK threw itself, so a test
 * exception made in `Worker\TestRun` would never be captured. Its message, file
 * and line are the same on every run, which is what makes the API count a
 * second run within 5 minutes as a duplicate.
 *
 * The message is the one the Laravel SDK's `ranetrace:test-errors` sends, so the
 * item is recognisable by its content: no field marks it as a test.
 */

return static fn (): Exception => new Exception('Test exception from Ranetrace');
