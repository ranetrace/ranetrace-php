<?php

declare(strict_types=1);

namespace Ranetrace\Php\Worker;

/**
 * What {@see TestRun} found, and the text `vendor/bin/ranetrace-test` prints.
 *
 * The wording lives here rather than in the binary so it can be asserted
 * in-process. A setting is named the way the reader set it: the binary reads
 * the environment only, so it renders with `fromEnvironment: true` and names
 * `RANETRACE_KEY`; a host that configured the SDK in its own bootstrap gets
 * the config key instead, and no sentence about an environment it did not use.
 */
final readonly class TestReport
{
    /**
     * Width of the label column, the longest label (`Waiting`) and two spaces.
     */
    private const int LABEL_WIDTH = 9;

    /**
     * @param  ?string  $keyPreview  The key's first four characters and `...`, or null when no key is set.
     * @param  array<string, array{outcome: TestOutcome, status: int, message: string, seconds: int}>  $types  Per tested type, empty when nothing was sent.
     * @param  array<string, int>  $waiting  Items waiting in the spool, only for the types holding any.
     * @param  ?int  $oldestWaitSeconds  How long the oldest waiting item has waited.
     * @param  list<array{scope: string, reason: string}>  $lifted  Pauses a 200 lifted, `scope` being `everything` or a type.
     * @param  list<array{scope: string, reason: string, seconds: int}>  $pauses  Pauses still active after the lifting, with their seconds left.
     */
    public function __construct(
        public ?string $keyPreview,
        public string $baseUrl,
        public bool $masterSwitchOn,
        public array $types,
        public string $bufferPath,
        public ?string $accessProblem,
        public array $waiting,
        public ?int $oldestWaitSeconds,
        public array $lifted,
        public array $pauses,
    ) {}

    /**
     * Whether the API accepted at least one test item.
     */
    public function accepted(): bool
    {
        foreach ($this->types as $result) {
            if ($result['outcome']->accepted()) {
                return true;
            }
        }

        return false;
    }

    /**
     * The whole report as plain text, newline-terminated.
     *
     * @param  bool  $fromEnvironment  Whether the configuration came from the environment only, as it does for the binary.
     */
    public function render(bool $fromEnvironment = false): string
    {
        $lines = ['Ranetrace test', ''];

        $key = $this->keyPreview === null ? 'not set' : $this->keyPreview.($fromEnvironment ? ' (RANETRACE_KEY)' : '');

        $lines[] = self::row('Key', $key);
        $lines[] = self::row('API', $this->baseUrl);
        $lines[] = '';

        $stop = $this->stop($fromEnvironment);

        if ($stop !== null) {
            $lines[] = '  '.$stop;
        }

        foreach ($this->types as $type => $result) {
            $lines[] = self::row($type, $this->typeLine($type, $result, $fromEnvironment));
        }

        $lines[] = '';

        array_push($lines, ...$this->statusLines());

        $lines[] = '';
        $lines[] = $this->accepted() ? 'Open your website in Ranetrace to see what was accepted.' : 'Nothing was accepted.';

        return implode("\n", $lines)."\n";
    }

    private static function row(string $label, string $value): string
    {
        return '  '.mb_str_pad($label, self::LABEL_WIDTH).$value;
    }

    /**
     * A line under the row above it, aligned with its value.
     */
    private static function continuation(string $value): string
    {
        return '  '.str_repeat(' ', self::LABEL_WIDTH).$value;
    }

    /**
     * @param  list<string>  $values
     * @return list<string>
     */
    private static function rows(string $label, array $values): array
    {
        $lines = [];

        foreach ($values as $index => $value) {
            $lines[] = $index === 0 ? self::row($label, $value) : self::continuation($value);
        }

        return $lines;
    }

    private static function reason(string $reason): string
    {
        return match ($reason) {
            'network' => 'a network failure',
            default => 'a '.$reason,
        };
    }

    private static function timeLeft(int $seconds): string
    {
        if ($seconds < 60) {
            return $seconds === 1 ? '1 more second' : "{$seconds} more seconds";
        }

        $minutes = (int) ceil($seconds / 60);

        return $minutes === 1 ? '1 more minute' : "{$minutes} more minutes";
    }

    private static function count(string $type, int $count): string
    {
        [$one, $many] = match ($type) {
            'errors' => ['error', 'errors'],
            'events' => ['event', 'events'],
            'logs' => ['log record', 'log records'],
            'javascript_errors' => ['JavaScript error', 'JavaScript errors'],
            default => [$type, $type],
        };

        return $count.' '.($count === 1 ? $one : $many);
    }

    /**
     * Why nothing was sent, when nothing was.
     */
    private function stop(bool $fromEnvironment): ?string
    {
        if (! $this->masterSwitchOn) {
            return ($fromEnvironment ? 'RANETRACE_ENABLED' : 'The enabled setting').' is false, so nothing is captured or sent.';
        }

        if ($this->keyPreview !== null) {
            return null;
        }

        if (! $fromEnvironment) {
            return 'No key is configured, so nothing is captured or sent.';
        }

        return "RANETRACE_KEY is not set in this command's environment, so nothing is captured or sent. "
            .'This command reads the environment only: a key your application loads from a .env file or sets in its bootstrap does not reach it.';
    }

    /**
     * @param  array{outcome: TestOutcome, status: int, message: string, seconds: int}  $result
     */
    private function typeLine(string $type, array $result, bool $fromEnvironment): string
    {
        return match ($result['outcome']) {
            TestOutcome::Accepted => 'accepted',
            TestOutcome::AcceptedNotStored => $type === 'errors'
                ? 'accepted, not stored: the API stores the same error once per 5 minutes and skips an error you set to ignored'
                : 'accepted, not stored: the API ignored it',
            TestOutcome::Refused => 'refused: the API did not store the test item. This is a bug in the SDK, please report it',
            TestOutcome::NotProcessed => 'not processed: the API ran out of time. Run the test again',
            TestOutcome::Unrecognised => "failed: the API answered 200 without counting the test item, so {$this->baseUrl} may not be the Ranetrace API",
            TestOutcome::Unauthorized => "refused: the API answered 401 ({$result['message']}). Check ".($fromEnvironment ? 'RANETRACE_KEY' : 'the configured key'),
            TestOutcome::Forbidden => "refused: the API answered 403 ({$result['message']}). The key lacks access to this feature, the website is in maintenance mode, or the account has no access",
            TestOutcome::RateLimited => 'rate limited: the API answered 429. Try again in '.($result['seconds'] === 1 ? '1 second' : "{$result['seconds']} seconds"),
            TestOutcome::Unreachable => "failed: could not reach {$this->baseUrl} ({$result['message']})",
            TestOutcome::Failed => "failed: the API answered {$result['status']} ({$result['message']})",
            TestOutcome::NotSent => 'not sent: the key was refused',
            TestOutcome::Skipped => 'skipped: '.($fromEnvironment ? 'RANETRACE_'.mb_strtoupper($type).'_ENABLED' : $type.'.enabled').' is false',
            TestOutcome::NotCaptured => $result['message'] === ''
                ? 'not captured: the SDK could not build the test item. Turn internal logging on to see why'
                : "not captured: the SDK could not build the test item. The reason is in {$result['message']}",
        };
    }

    /**
     * @return list<string>
     */
    private function statusLines(): array
    {
        $lines = [self::row('Buffer', $this->bufferPath)];

        if ($this->accessProblem !== null) {
            $lines[] = self::continuation("This user cannot use it: {$this->accessProblem}. Run the cron flush as the user your web server runs as.");
        } else {
            $lines[] = self::row('Waiting', $this->waitingSummary());

            if ($this->oldestWaitSeconds !== null && $this->oldestWaitSeconds >= TestRun::STALE_SECONDS) {
                $minutes = intdiv($this->oldestWaitSeconds, 60);
                $stale = "The oldest has waited {$minutes} minutes.";

                if ($this->pauses === []) {
                    $stale .= ' Nothing has drained the buffer in that time: check the cron line for vendor/bin/ranetrace-flush.';
                }

                $lines[] = self::continuation($stale);
            }
        }

        $lifted = array_map(
            fn (array $pause): string => 'the pause on '.$pause['scope'].' (after '.self::reason($pause['reason']).'): '
                .($pause['scope'] === 'everything' ? 'the key is accepted now' : "the {$pause['scope']} endpoint answered 200 just now"),
            $this->lifted,
        );

        array_push($lines, ...self::rows('Lifted', $lifted));

        $pauses = array_map(
            static fn (array $pause): string => $pause['scope'].', for '.self::timeLeft($pause['seconds']).' (after '.self::reason($pause['reason']).')',
            $this->pauses,
        );

        array_push($lines, ...self::rows('Pauses', $pauses === [] ? ['none'] : $pauses));

        return $lines;
    }

    private function waitingSummary(): string
    {
        if ($this->waiting === []) {
            return 'nothing';
        }

        $parts = [];

        foreach ($this->waiting as $type => $count) {
            $parts[] = self::count($type, $count);
        }

        return implode(', ', $parts);
    }
}
