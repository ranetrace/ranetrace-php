<?php

declare(strict_types=1);

namespace Ranetrace\Php\Worker;

use Ranetrace\Php\Http\BatchCounters;
use Ranetrace\Php\Http\ResponsePolicy;

/**
 * The result of one type's test: what the API's answer to one test item means,
 * and the line that says so.
 *
 * Shared by every SDK that sends a test item, so the same answer reads the same
 * way and prints the same line everywhere: {@see TestRun} and {@see TestReport}
 * for `vendor/bin/ranetrace-test`, and `ranetrace/ranetrace-laravel`'s
 * `ranetrace:test`, which prints its own lines around these. What a status
 * means for a batch is {@see ResponsePolicy}'s decision; this class decides
 * what it means for one test item, and words it. The lines here are quoted in
 * texts outside this package, so their wording is part of the contract with
 * the reader.
 */
final readonly class TestResult
{
    /**
     * Feature pause reasons a 200 does not lift. A 429 pause lasts as long as
     * the server said it should. A 413 or a 422 was the answer to one batch,
     * and one accepted item says nothing about that batch.
     *
     * @var list<string>
     */
    private const array PAUSES_A_200_KEEPS = ['429', '413', '422'];

    private function __construct(
        public TestOutcome $outcome,
        public int $status = 0,
        public string $message = '',
        public int $seconds = 0,
    ) {}

    /**
     * Read one normalised API result: the array `Worker::send()` returns, or
     * the Laravel client's, whose `headers` may be empty and whose `error` key
     * may be absent.
     *
     * @param  array{status?: int, data?: array<string, mixed>, headers?: array<string, mixed>, error?: ?string}  $result
     */
    public static function fromResponse(array $result): self
    {
        $outcome = new ResponsePolicy()->decide($result);
        $body = is_array($result['data'] ?? null) ? $result['data'] : [];

        return match ($outcome->status) {
            0 => new self(TestOutcome::Unreachable, message: $result['error'] ?? 'unknown network error'),
            200 => new self(self::outcomeOfSuccess($outcome->counters), 200),
            401 => new self(TestOutcome::Unauthorized, 401, ResponsePolicy::errorMessage($body, 'Unauthorized')),
            403 => new self(TestOutcome::Forbidden, 403, ResponsePolicy::errorMessage($body, 'Forbidden')),
            429 => new self(TestOutcome::RateLimited, 429, seconds: $outcome->pauseSeconds ?? ResponsePolicy::RATE_LIMIT_FLOOR_SECONDS),
            default => new self(TestOutcome::Failed, $outcome->status, ResponsePolicy::errorMessage($body, 'no message')),
        };
    }

    /**
     * The type's own feature flag is off.
     */
    public static function skipped(): self
    {
        return new self(TestOutcome::Skipped);
    }

    /**
     * An earlier type met a 401, so this one was not sent.
     */
    public static function notSent(): self
    {
        return new self(TestOutcome::NotSent);
    }

    /**
     * The capture path left no item to send.
     *
     * @param  string  $logFile  Where the capture path wrote why, or `''` when internal logging is off.
     */
    public static function notCaptured(string $logFile): self
    {
        return new self(TestOutcome::NotCaptured, message: $logFile);
    }

    /**
     * Whether a 200 lifts a feature pause the server set for this reason.
     */
    public static function liftsFeaturePause(string $reason): bool
    {
        return ! in_array($reason, self::PAUSES_A_200_KEEPS, true);
    }

    /**
     * The sentence for one pause a 200 lifted.
     *
     * @param  string  $scope  `everything` for the global pause, otherwise the type.
     * @param  string  $reason  The reason the pause was set with, as the pause store holds it.
     */
    public static function liftedPauseLine(string $scope, string $reason): string
    {
        return 'the pause on '.$scope.' (after '.self::pauseReason($reason).'): '
            .($scope === 'everything' ? 'the key is accepted now' : "the {$scope} endpoint answered 200 just now");
    }

    /**
     * What a pause reason, as the pause store holds it, reads as after "after".
     */
    public static function pauseReason(string $reason): string
    {
        return match ($reason) {
            'network' => 'a network failure',
            default => 'a '.$reason,
        };
    }

    /**
     * The sentence a test ends on.
     *
     * @param  bool  $accepted  Whether the API accepted at least one test item.
     */
    public static function closingLine(bool $accepted): string
    {
        return $accepted ? 'Open your website in Ranetrace to see what was accepted.' : 'Nothing was accepted.';
    }

    public function accepted(): bool
    {
        return $this->outcome->accepted();
    }

    /**
     * Whether this answer disproves the pauses real traffic left: a 200 from
     * the Ranetrace API, whatever it counted. A 200 that counted nothing may
     * not have come from that API at all.
     */
    public function disprovesPauses(): bool
    {
        return $this->status === 200 && $this->outcome !== TestOutcome::Unrecognised;
    }

    /**
     * The type's line, without its label.
     *
     * @param  bool  $fromEnvironment  Whether the configuration came from the environment only, so a setting is named by its variable.
     */
    public function line(string $type, string $baseUrl, bool $fromEnvironment): string
    {
        return match ($this->outcome) {
            TestOutcome::Accepted => 'accepted',
            TestOutcome::AcceptedNotStored => $type === 'errors'
                ? 'accepted, not stored: the API stores the same error once per 5 minutes and skips an error you set to ignored'
                : 'accepted, not stored: the API ignored it',
            TestOutcome::Refused => 'refused: the API did not store the test item. This is a bug in the SDK, please report it',
            TestOutcome::NotProcessed => 'not processed: the API ran out of time. Run the test again',
            TestOutcome::Unrecognised => "failed: the API answered 200 without counting the test item, so {$baseUrl} may not be the Ranetrace API",
            TestOutcome::Unauthorized => "refused: the API answered 401 ({$this->message}). Check ".($fromEnvironment ? 'RANETRACE_KEY' : 'the configured key'),
            TestOutcome::Forbidden => "refused: the API answered 403 ({$this->message}). The key lacks access to this feature, the website is in maintenance mode, or the account has no access",
            TestOutcome::RateLimited => 'rate limited: the API answered 429. Try again in '.($this->seconds === 1 ? '1 second' : "{$this->seconds} seconds"),
            TestOutcome::Unreachable => "failed: could not reach {$baseUrl} ({$this->message})",
            TestOutcome::Failed => "failed: the API answered {$this->status} ({$this->message})",
            TestOutcome::NotSent => 'not sent: the key was refused',
            TestOutcome::Skipped => 'skipped: '.($fromEnvironment ? 'RANETRACE_'.mb_strtoupper($type).'_ENABLED' : $type.'.enabled').' is false',
            TestOutcome::NotCaptured => $this->message === ''
                ? 'not captured: the SDK could not build the test item. Turn internal logging on to see why'
                : "not captured: the SDK could not build the test item. The reason is in {$this->message}",
        };
    }

    /**
     * What a 200 said about the one item it was sent. One item means exactly
     * one counter is 1. A 200 that counts nothing, which is also what a body
     * that is not JSON reads as, did not come from the Ranetrace API as it is
     * documented, so it is not taken as an acceptance.
     */
    private static function outcomeOfSuccess(?BatchCounters $counters): TestOutcome
    {
        return match (true) {
            $counters === null => TestOutcome::Unrecognised,
            $counters->failed > 0 => TestOutcome::Refused,
            $counters->unprocessed > 0 => TestOutcome::NotProcessed,
            $counters->ignored > 0 => TestOutcome::AcceptedNotStored,
            $counters->processed > 0 => TestOutcome::Accepted,
            default => TestOutcome::Unrecognised,
        };
    }
}
