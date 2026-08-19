<?php

declare(strict_types=1);

namespace Ranetrace\Php\Logging;

use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Level;
use Monolog\LogRecord;
use Ranetrace\Php\Buffer\BufferInterface;
use Ranetrace\Php\Config;
use Ranetrace\Php\Support\DataSanitizer;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\ItemByteBudget;
use Ranetrace\Php\Support\PayloadSizer;
use Ranetrace\Php\Support\SecretScrubber;
use Throwable;

/**
 * Monolog handler that captures log records into the `logs` buffer.
 *
 * Ported from `ranetrace/ranetrace-laravel`
 * (`src/Logging/RanetraceLogHandler.php`). The six-key payload, the caps and
 * the `_truncated` marker wording are the wire contract and must not drift from
 * that SDK. Only two things changed: the record is written to the file buffer
 * instead of dispatched as a queued job, and the environment trio attached to
 * `extra` names the framework generically (`framework`, `framework_version`)
 * rather than reporting `laravel_version`.
 *
 * Per-field caps bound the size of a SINGLE captured log item. They do not by
 * themselves keep a 1000-item batch under the API's 5MB request limit; that is
 * the worker's pre-flight byte-budget trim. NOT user-tunable: raising any of
 * them widens per-item size and the 413 risk.
 */
final class RanetraceHandler extends AbstractProcessingHandler
{
    private const string TRUNCATION_SUFFIX = '... (truncated)';

    private const int MAX_MESSAGE_LENGTH = 50_000;

    private const int MAX_CONTEXT_BYTES = 51_200;

    private const int MAX_EXTRA_BYTES = 10_240;

    private readonly ItemByteBudget $budget;

    /**
     * The minimum level defaults to the configured `logging.level` (itself
     * `notice`) rather than to Monolog's `debug`, so a host that mounts this
     * handler without arguments gets the level its Ranetrace config already
     * names instead of a firehose.
     */
    public function __construct(
        private readonly Config $config,
        private readonly BufferInterface $buffer,
        private readonly SecretScrubber $scrubber,
        private readonly InternalLogger $log,
        int|string|Level|null $level = null,
        bool $bubble = true,
    ) {
        parent::__construct($level ?? self::configuredLevel($config), $bubble);

        $this->budget = new ItemByteBudget($log);
    }

    /**
     * Buffer one record.
     *
     * The whole body is wrapped in try/catch: this handler sits in the host
     * application's `$logger->error(...)` call path, so it must never throw
     * back into the caller's business code.
     */
    protected function write(LogRecord $record): void
    {
        try {
            if (! $this->config->enabled('logging')) {
                return;
            }

            if ($this->isExcludedChannel($record->channel)) {
                return;
            }

            // The per-item byte budget runs on the finished, already scrubbed
            // item, right before it reaches the buffer. A null item was
            // irreducibly over budget and was dropped with a diagnostics entry,
            // so there is nothing left to buffer.
            $item = $this->budget->cap('logs', [
                'level' => mb_strtolower($record->level->name),
                'message' => $this->message($record->message),
                'context' => PayloadSizer::capBytes(
                    (array) $this->scrubber->scrubDeep(DataSanitizer::sanitizeForSerialization($record->context)),
                    self::MAX_CONTEXT_BYTES,
                    'Context exceeded 50KB limit and was removed',
                ),
                'channel' => $record->channel,
                'timestamp' => $record->datetime->format('c'),
                'extra' => $this->extra($record),
            ]);

            if ($item === null) {
                return;
            }

            $this->buffer->addItem('logs', $item);
        } catch (Throwable $failure) {
            $this->log->warning('Failed to capture log to Ranetrace', [
                'exception' => $failure->getMessage(),
            ]);
        }
    }

    /**
     * The configured minimum level. A value Monolog cannot read is a
     * misconfiguration the developer can still fix, so it is left to Monolog to
     * reject loudly rather than silently downgraded.
     */
    private static function configuredLevel(Config $config): int|string
    {
        $level = $config->get('logging.level', 'notice');

        return is_int($level) || is_string($level) ? $level : 'notice';
    }

    /**
     * Scrub key=value secrets BEFORE truncating, so a secret cannot survive by
     * being split across the length boundary.
     */
    private function message(string $message): string
    {
        $message = $this->scrubber->scrubString($message);

        if (mb_strlen($message) <= self::MAX_MESSAGE_LENGTH) {
            return $message;
        }

        return mb_substr($message, 0, self::MAX_MESSAGE_LENGTH - mb_strlen(self::TRUNCATION_SUFFIX)).self::TRUNCATION_SUFFIX;
    }

    /**
     * The record's own extra, capped, plus the environment trio.
     *
     * Only the user-supplied part is capped, and the trio is attached
     * afterwards, so the triage metadata survives even when the user extra is
     * dropped wholesale for being oversized. `framework` and
     * `framework_version` appear only when the host configured them: `extra` is
     * not strict-field-validated, so an absent key costs nothing, while a null
     * one would read as "no framework" rather than "not said".
     *
     * @return array<string, mixed>
     */
    private function extra(LogRecord $record): array
    {
        $extra = PayloadSizer::capBytes(
            (array) $this->scrubber->scrubDeep(DataSanitizer::sanitizeForSerialization($record->extra)),
            self::MAX_EXTRA_BYTES,
            'Extra data exceeded 10KB limit and was removed',
        );

        $environment = $this->config->get('environment');

        $trio = [
            'environment' => is_scalar($environment) ? (string) $environment : '',
            'php_version' => (string) phpversion(),
        ];

        foreach (['framework', 'framework_version'] as $key) {
            $value = $this->config->get($key);

            if (is_string($value) && $value !== '') {
                $trio[$key] = $value;
            }
        }

        return array_merge($extra, $trio);
    }

    private function isExcludedChannel(string $channel): bool
    {
        $excluded = $this->config->get('logging.excluded_channels', []);

        return is_array($excluded) && in_array($channel, $excluded, true);
    }
}
