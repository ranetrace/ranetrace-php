<?php

declare(strict_types=1);

namespace Ranetrace\Php\Logging;

use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Level;
use Monolog\LogRecord;
use Ranetrace\Php\Buffer\BufferInterface;
use Ranetrace\Php\Config;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\ItemByteBudget;
use Ranetrace\Php\Support\SecretScrubber;
use Throwable;

/**
 * Monolog handler that captures log records into the `logs` buffer.
 *
 * The item's shape lives in {@see LogItemBuilder}, shared with
 * `ranetrace/ranetrace-laravel` so the six-key payload, the caps and the
 * `_truncated` marker wording cannot drift between the two SDKs. What is left
 * here is this SDK's own half: the gates, and writing to the file buffer rather
 * than dispatching a queued job.
 */
final class RanetraceHandler extends AbstractProcessingHandler
{
    private readonly ItemByteBudget $budget;

    private readonly LogItemBuilder $items;

    /**
     * The minimum level defaults to the configured `logging.level` (itself
     * `notice`) rather than to Monolog's `debug`, so a host that mounts this
     * handler without arguments gets the level its Ranetrace config already
     * names instead of a firehose.
     */
    public function __construct(
        private readonly Config $config,
        private readonly BufferInterface $buffer,
        SecretScrubber $scrubber,
        private readonly InternalLogger $log,
        int|string|Level|null $level = null,
        bool $bubble = true,
    ) {
        parent::__construct($level ?? self::configuredLevel($config), $bubble);

        $this->budget = new ItemByteBudget($log);
        $this->items = new LogItemBuilder($config, $scrubber);
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
            $item = $this->budget->cap('logs', $this->items->build(
                $record->level->name,
                $record->message,
                $record->context,
                $record->channel,
                $record->datetime->format('c'),
                $record->extra,
            ));

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

    private function isExcludedChannel(string $channel): bool
    {
        $excluded = $this->config->get('logging.excluded_channels', []);

        return is_array($excluded) && in_array($channel, $excluded, true);
    }
}
