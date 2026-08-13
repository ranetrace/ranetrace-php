<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use DateTimeImmutable;
use Ranetrace\Php\Config;
use Throwable;

/**
 * The SDK's own diagnostics sink: why a batch failed, why a feature paused, why
 * an item was dropped.
 *
 * Ported from `ranetrace/ranetrace-laravel` (`src/Support/InternalLogger.php`),
 * where it wrote to a dedicated `ranetrace_internal` Monolog channel. Here it
 * owns a plain daily file under the buffer directory instead, for the same
 * reason the Laravel SDK insisted on a separate channel: this logger must never
 * reach the capture path. If SDK diagnostics went through the application's
 * logger, and the application routes its logger back into Ranetrace, a failing
 * send would log a failure that is captured, buffered and sent, which fails
 * again. The isolation is the whole point, so it must survive any refactor.
 *
 * Nothing here throws. A logger that can break the host while reporting that
 * something is already broken is worse than a logger that stays quiet.
 */
final class InternalLogger
{
    /**
     * PSR-3 severities in ascending order; the configured minimum is compared
     * against these.
     *
     * @var array<string, int>
     */
    private const array LEVELS = [
        'debug' => 0,
        'info' => 1,
        'notice' => 2,
        'warning' => 3,
        'error' => 4,
        'critical' => 5,
        'alert' => 6,
        'emergency' => 7,
    ];

    /**
     * Retention runs once per instance rather than per write: it is a directory
     * scan, and the capture path can call this logger many times per request.
     */
    private bool $pruned = false;

    public function __construct(private readonly Config $config) {}

    /**
     * @param  array<string, mixed>  $context
     */
    public function debug(string $message, array $context = []): void
    {
        $this->log('debug', $message, $context);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public function info(string $message, array $context = []): void
    {
        $this->log('info', $message, $context);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public function notice(string $message, array $context = []): void
    {
        $this->log('notice', $message, $context);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public function warning(string $message, array $context = []): void
    {
        $this->log('warning', $message, $context);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public function error(string $message, array $context = []): void
    {
        $this->log('error', $message, $context);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public function critical(string $message, array $context = []): void
    {
        $this->log('critical', $message, $context);
    }

    /**
     * Write one record, honouring the enabled flag and the minimum level.
     * Falls back to stderr when the file cannot be written, and to silence when
     * even that fails.
     *
     * @param  array<string, mixed>  $context
     */
    public function log(string $level, string $message, array $context = []): void
    {
        try {
            if ($this->config->get('internal_logging.enabled', true) !== true) {
                return;
            }

            $level = mb_strtolower($level);

            if (! $this->passesLevel($level)) {
                return;
            }

            if ($this->writeToFile($this->format($level, $message, $context))) {
                return;
            }

            $this->writeToStderr($level, $message, $context, null);
        } catch (Throwable $failure) {
            $this->writeToStderr($level, $message, $context, $failure);
        }
    }

    /**
     * Absolute path of today's log file. Exposed so diagnostics tooling can
     * point an operator at it.
     */
    public function currentLogFile(?DateTimeImmutable $now = null): string
    {
        $now ??= new DateTimeImmutable;

        return $this->directory().'/internal-'.$now->format('Y-m-d').'.log';
    }

    private function passesLevel(string $level): bool
    {
        if (! isset(self::LEVELS[$level])) {
            return false;
        }

        $configured = $this->config->get('internal_logging.level', 'debug');
        $minimum = is_string($configured) ? mb_strtolower($configured) : 'debug';

        return self::LEVELS[$level] >= (self::LEVELS[$minimum] ?? 0);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function format(string $level, string $message, array $context): string
    {
        $encoded = $context === [] ? '' : ' '.(string) json_encode($context, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);

        return sprintf(
            '[%s] ranetrace_internal.%s: %s%s%s',
            (new DateTimeImmutable)->format('c'),
            mb_strtoupper($level),
            $message,
            $encoded,
            PHP_EOL,
        );
    }

    /**
     * @return bool Whether the line reached the file.
     */
    private function writeToFile(string $line): bool
    {
        $directory = $this->directory();

        if (! is_dir($directory) && ! $this->quietly(fn (): bool => mkdir($directory, 0775, true)) && ! is_dir($directory)) {
            return false;
        }

        $this->prune($directory);

        return $this->quietly(fn (): mixed => file_put_contents($this->currentLogFile(), $line, FILE_APPEND | LOCK_EX)) !== false;
    }

    /**
     * Drop day files older than the configured retention. Best-effort: a file
     * that cannot be deleted is left where it is.
     */
    private function prune(string $directory): void
    {
        if ($this->pruned) {
            return;
        }

        $this->pruned = true;

        $days = $this->config->get('internal_logging.days', 14);
        $days = is_numeric($days) ? (int) $days : 14;

        if ($days < 1) {
            return;
        }

        $files = $this->quietly(fn (): mixed => glob($directory.'/internal-*.log'));

        if (! is_array($files)) {
            return;
        }

        $cutoff = (new DateTimeImmutable)->modify('-'.$days.' days')->format('Y-m-d');

        foreach ($files as $file) {
            if (preg_match('/internal-(\d{4}-\d{2}-\d{2})\.log$/', $file, $matches) !== 1) {
                continue;
            }

            if ($matches[1] < $cutoff) {
                $this->quietly(fn (): mixed => unlink($file));
            }
        }
    }

    /**
     * Last resort when the file sink is unavailable, e.g. an unwritable buffer
     * directory. Guarded by its own try/catch: if stderr is gone too, silence is
     * the only remaining correct behaviour.
     *
     * @param  array<string, mixed>  $context
     */
    private function writeToStderr(string $level, string $message, array $context, ?Throwable $failure): void
    {
        try {
            if ($this->config->get('internal_logging.stderr_fallback', true) !== true) {
                return;
            }

            $formattedContext = $context === [] ? '' : ' | Context: '.(string) json_encode($context, JSON_PARTIAL_OUTPUT_ON_ERROR);
            $formattedFailure = $failure instanceof Throwable ? ' | Sink Error: '.$failure->getMessage() : '';

            $this->quietly(fn (): mixed => error_log(sprintf(
                '[Ranetrace Internal %s] %s%s%s',
                mb_strtoupper($level),
                $message,
                $formattedContext,
                $formattedFailure
            )));
        } catch (Throwable) {
            // Absolute silence as last resort. If we cannot even write to
            // stderr, there is nothing more we can do.
        }
    }

    /**
     * Run a filesystem call with PHP's error reporting muted.
     *
     * The `@` operator is not enough: it still invokes whatever error handler
     * the host installed, and this logger's whole reason to exist is that its
     * own failures must not surface anywhere the host might route back into
     * Ranetrace. An unwritable buffer directory is expected and handled by the
     * return value, not by a warning.
     *
     * Deliberately not `Support\Quietly`, which swallows a `Throwable` into
     * `false`. Here a throwing sink has to reach `log()`'s catch so the record
     * still gets its stderr fallback, so this copy only mutes the error handler
     * and lets exceptions through.
     */
    private function quietly(callable $callback): mixed
    {
        set_error_handler(static fn (): bool => true);

        try {
            return $callback();
        } finally {
            restore_error_handler();
        }
    }

    private function directory(): string
    {
        return $this->config->bufferPath();
    }
}
