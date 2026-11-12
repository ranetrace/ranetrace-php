<?php

declare(strict_types=1);

namespace Ranetrace\Php\Worker;

use Exception;
use Ranetrace\Php\Buffer\FileBuffer;
use Ranetrace\Php\Buffer\MemoryBuffer;
use Ranetrace\Php\Buffer\PauseStore;
use Ranetrace\Php\Config;
use Ranetrace\Php\Errors\ErrorReporter;
use Ranetrace\Php\Events\EventTracker;
use Ranetrace\Php\Support\FingerprintGenerator;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;

/**
 * Sends one test error and one test event straight to the API, and reads the
 * state of the spool and the pauses, for `vendor/bin/ranetrace-test`.
 *
 * The test goes beside the spool, never through it. The items are captured
 * through the real capture path into a {@see MemoryBuffer} and sent with
 * {@see Worker::send()}, so they are shaped and sent exactly like real ones,
 * but the answer is only read: nothing is buffered, re-buffered or paused. A
 * test that ran through the real flush would turn a wrong key into a 15 minute
 * pause on everything, and the developer who fixes the key and runs the test
 * again would be told "paused".
 *
 * The one write is the other way round. A 200 disproves some pauses real
 * traffic left behind, so it lifts them: a global pause, which only a 401 sets,
 * and the type's own pause, unless the server set it for a reason one accepted
 * item says nothing about (see {@see TestResult::liftsFeaturePause()}).
 *
 * What an answer means for the test item, and how it reads, is
 * {@see TestResult}'s, shared with the Laravel SDK's test command. This class
 * decides what to send and what to lift.
 *
 * The items carry no test marker, because the API matches the field set
 * strictly. They are recognisable by content, the same content the Laravel
 * SDK's test commands send.
 */
final class TestRun
{
    /**
     * The types the test sends, in the order it sends them.
     *
     * @var list<string>
     */
    public const array TYPES = ['errors', 'events'];

    /**
     * An item waiting at least this long gets a line of its own in the status
     * block: a cron flush that runs every minute never lets one get this old.
     */
    public const int STALE_SECONDS = 600;

    public function __construct(
        private readonly Config $config,
        private readonly FileBuffer $buffer,
        private readonly PauseStore $pauses,
        private readonly Worker $worker,
        private readonly SecretScrubber $scrubber,
        private readonly FingerprintGenerator $fingerprints,
        private readonly InternalLogger $log,
    ) {}

    public function run(): TestReport
    {
        $key = $this->config->key();
        $masterSwitchOn = $this->config->get('enabled') === true;

        $types = [];
        $lifted = [];

        if ($masterSwitchOn && $key !== '') {
            $keyRefused = false;

            foreach (self::TYPES as $type) {
                $types[$type] = $this->test($type, $keyRefused, $lifted);

                $keyRefused = $keyRefused || $types[$type]->outcome === TestOutcome::Unauthorized;
            }
        }

        $problem = $this->buffer->accessProblem();
        [$waiting, $oldest] = $problem === null ? $this->waiting() : [[], null];

        return new TestReport(
            keyPreview: $key === '' ? null : mb_substr($key, 0, 4).'...',
            baseUrl: $this->config->baseUrl(),
            masterSwitchOn: $masterSwitchOn,
            types: $types,
            bufferPath: $this->config->bufferPath(),
            accessProblem: $problem,
            waiting: $waiting,
            oldestWaitSeconds: $oldest === null ? null : max(0, time() - $oldest),
            lifted: $lifted,
            pauses: $this->activePauses(),
        );
    }

    private static function secondsLeft(string $pausedUntil): int
    {
        $until = strtotime($pausedUntil);

        return $until === false ? 0 : max(1, $until - time());
    }

    /**
     * Capture, send and read one type.
     *
     * A type whose feature is off says so even after a 401, because that is
     * the reason it would not be sent either way. Otherwise a key an earlier
     * type had refused is not presented again: every endpoint refuses it, as
     * the worker reasons.
     *
     * @param  bool  $keyRefused  Whether an earlier type met a 401.
     * @param  list<array{scope: string, reason: string}>  $lifted  Receives the pauses this type's 200 lifted.
     */
    private function test(string $type, bool $keyRefused, array &$lifted): TestResult
    {
        if ($this->config->get($type.'.enabled') !== true) {
            return TestResult::skipped();
        }

        if ($keyRefused) {
            return TestResult::notSent();
        }

        $item = $this->capture($type);

        if ($item === null) {
            $logging = $this->config->get('internal_logging.enabled', true) === true;

            return TestResult::notCaptured($logging ? $this->log->currentLogFile() : '');
        }

        $tested = TestResult::fromResponse($this->worker->send($type, [$item]));

        if ($tested->disprovesPauses()) {
            array_push($lifted, ...$this->liftPausesDisprovedBy($type));
        }

        return $tested;
    }

    /**
     * The one test item of a type, built by the real capture path, or null when
     * that path left nothing (it has already written why to the internal log).
     *
     * @return array<string, mixed>|null
     */
    private function capture(string $type): ?array
    {
        $buffer = new MemoryBuffer;

        if ($type === 'errors') {
            /** @var callable(): Exception $exception */
            $exception = require dirname(__DIR__, 2).'/resources/test-exception.php';

            new ErrorReporter($this->config, $buffer, $this->scrubber, $this->log)->report($exception());
        } else {
            new EventTracker($this->config, $buffer, $this->scrubber, $this->fingerprints, $this->log)
                ->track('test_event', ['source' => 'ranetrace-test']);
        }

        return $buffer->take($type, 1)[0]['data'] ?? null;
    }

    /**
     * Clear the pauses a 200 for this type disproves, and name each one that
     * is really gone afterwards: a clear can lose its lock, and a pause that is
     * still there must be reported as active rather than as lifted.
     *
     * @return list<array{scope: string, reason: string}>
     */
    private function liftPausesDisprovedBy(string $type): array
    {
        $lifted = [];

        $global = $this->pauses->globalPause();

        if ($global !== null) {
            $this->pauses->clearGlobalPause();

            if (! $this->pauses->isGloballyPaused()) {
                $lifted[] = ['scope' => 'everything', 'reason' => $global['reason']];
            }
        }

        $feature = $this->pauses->featurePause($type);

        if ($feature !== null && TestResult::liftsFeaturePause($feature['reason'])) {
            $this->pauses->clearFeaturePause($type);

            if (! $this->pauses->isFeaturePaused($type)) {
                $lifted[] = ['scope' => $type, 'reason' => $feature['reason']];
            }
        }

        return $lifted;
    }

    /**
     * The types holding items, with their counts, and the capture time of the
     * oldest item among them.
     *
     * @return array{0: array<string, int>, 1: ?int}
     */
    private function waiting(): array
    {
        $waiting = [];
        $oldest = null;

        foreach ($this->buffer->types() as $type) {
            $count = $this->buffer->count($type);

            if ($count === 0) {
                continue;
            }

            $waiting[$type] = $count;
            $timestamp = $this->buffer->oldestTimestamp($type);

            if ($timestamp !== null && ($oldest === null || $timestamp < $oldest)) {
                $oldest = $timestamp;
            }
        }

        return [$waiting, $oldest];
    }

    /**
     * Every pause still active, the global one first, with the seconds it has
     * left.
     *
     * @return list<array{scope: string, reason: string, seconds: int}>
     */
    private function activePauses(): array
    {
        $pauses = [];

        $global = $this->pauses->globalPause();

        if ($global !== null) {
            $pauses[] = ['scope' => 'everything', 'reason' => $global['reason'], 'seconds' => self::secondsLeft($global['paused_until'])];
        }

        foreach ($this->buffer->types() as $type) {
            $feature = $this->pauses->featurePause($type);

            if ($feature !== null) {
                $pauses[] = ['scope' => $type, 'reason' => $feature['reason'], 'seconds' => self::secondsLeft($feature['paused_until'])];
            }
        }

        return $pauses;
    }
}
