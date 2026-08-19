<?php

declare(strict_types=1);

namespace Ranetrace\Php\Errors;

use ErrorException;
use Ranetrace\Php\Buffer\BufferInterface;
use Ranetrace\Php\Config;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\ItemByteBudget;
use Ranetrace\Php\Support\SecretScrubber;
use Throwable;

/**
 * Captures throwables into the `errors` buffer.
 *
 * Ported from `ranetrace/ranetrace-laravel` (`src/Ranetrace.php::report()`).
 * The gating, the self-protection guard and the never-throw posture are the
 * parts that matter and must not drift; the payload shaping lives in
 * {@see PayloadBuilder}.
 *
 * Where the Laravel SDK is wired into the framework's exception handler by the
 * host, this SDK installs PHP's own handlers itself via {@see register()}.
 */
final class ErrorReporter
{
    private readonly PayloadBuilder $payloadBuilder;

    private readonly ItemByteBudget $budget;

    /**
     * The exception handler that was installed before ours, called after we
     * report so the host's own handling still happens.
     *
     * @var callable(Throwable): void|null
     */
    private $previousExceptionHandler = null;

    /**
     * An explicit request context, for a host that has one (or a test that
     * needs the request branch under the CLI SAPI). Null means "read the live
     * superglobal".
     *
     * @var array<array-key, mixed>|null
     */
    private ?array $server = null;

    /**
     * An explicit answer to "is this a console process". Null means "ask
     * PHP_SAPI".
     */
    private ?bool $console = null;

    private bool $registered = false;

    private bool $fatalReported = false;

    public function __construct(
        private readonly Config $config,
        private readonly BufferInterface $buffer,
        private readonly SecretScrubber $scrubber,
        private readonly InternalLogger $log,
    ) {
        $this->payloadBuilder = new PayloadBuilder($config, $scrubber, $log);
        $this->budget = new ItemByteBudget($log);
    }

    /**
     * Capture one throwable. Never throws: losing a single error report is
     * acceptable, breaking the host application is not.
     */
    public function report(Throwable $throwable): void
    {
        if (! $this->config->enabled('errors')) {
            return;
        }

        // Never capture a throwable this SDK itself threw. The host wires
        // report() into its exception handling, so without this guard a
        // transport failure or an internal bug would be reported as one of the
        // host's application errors and loop straight back into Ranetrace.
        //
        // Detection is by throw site only, deliberately NOT by walking the
        // trace: SDK frames sit in the call stack of anything that reports, so
        // a trace-based check would misclassify ordinary host exceptions as
        // internal and silently stop capturing them.
        if ($this->isInternalThrowable($throwable)) {
            return;
        }

        try {
            // The per-item byte budget runs on the finished, already scrubbed
            // payload, right before it reaches the buffer. A null item was
            // irreducibly over budget and was dropped with a diagnostics entry,
            // so there is nothing left to buffer.
            $item = $this->budget->cap('errors', $this->payloadBuilder->build(
                $throwable,
                $this->server ?? $_SERVER,
                $this->console ?? (PHP_SAPI === 'cli'),
            ));

            if ($item === null) {
                return;
            }

            $this->buffer->addItem('errors', $item);
        } catch (Throwable $failure) {
            $this->log->error('Failed to capture exception', [
                'exception' => $failure->getMessage(),
            ]);
        }
    }

    /**
     * Install PHP's exception and shutdown handlers.
     *
     * Two handlers, because they cover two disjoint failure modes:
     *
     * - `set_exception_handler` catches uncaught exceptions. The handler that
     *   was already installed is kept and called after we report, so wiring
     *   Ranetrace in never takes over the host's own error page. When there was
     *   no previous handler the throwable is rethrown after reporting, so PHP
     *   still prints its own "Uncaught exception" report and exits non-zero,
     *   exactly as it would have without this SDK installed. Returning instead
     *   would swallow that output and turn a crash into a silent exit 0, which
     *   is how Sentry's SDK handles the same case.
     * - `register_shutdown_function` catches fatal errors (E_ERROR, E_PARSE,
     *   E_CORE_ERROR, E_COMPILE_ERROR). Those never reach an exception handler
     *   at all, so the last error of a dying process is inspected on the way
     *   out and reported as a synthesized {@see ErrorException}.
     *
     * `set_error_handler` is deliberately NOT installed. Notices, warnings and
     * deprecations are not errors this SDK reports, and taking over the error
     * handler would change how the host's own error reporting behaves for
     * every one of them. This matches the Laravel SDK's scope, which only ever
     * hooks the exception path.
     */
    public function register(): void
    {
        if ($this->registered) {
            return;
        }

        $this->registered = true;

        $previous = set_exception_handler($this->handleUncaughtThrowable(...));

        $this->previousExceptionHandler = is_callable($previous) ? $previous : null;

        register_shutdown_function($this->reportFatalError(...));
    }

    /**
     * Report the fatal error a dying process left behind, if it left one.
     *
     * Public because it is the shutdown callback, and because a fatal error
     * cannot be provoked inside a test process without ending it.
     *
     * @param  array{type: int, message: string, file: string, line: int}|null  $error  Defaults to `error_get_last()`.
     */
    public function reportFatalError(?array $error = null): void
    {
        if ($this->fatalReported) {
            return;
        }

        $error ??= error_get_last();

        if ($error === null || ! $this->isFatal($error['type'])) {
            return;
        }

        $this->fatalReported = true;

        $this->report(new ErrorException(
            $error['message'],
            0,
            $error['type'],
            $error['file'],
            $error['line'],
        ));
    }

    /**
     * Report from an explicit request context instead of the live `$_SERVER`.
     *
     * A host that has already normalised its request (or a test that needs the
     * request branch while running under the CLI SAPI) passes it here. Passing
     * `$isConsole` overrides the `PHP_SAPI` check, which is the only way to
     * reach either branch deterministically.
     *
     * @param  array<array-key, mixed>  $server
     */
    public function setServerContext(array $server, ?bool $isConsole = null): void
    {
        $this->server = $server;
        $this->console = $isConsole;
    }

    /**
     * Only the error types that kill the process. Notices, warnings and
     * deprecations are left to the host: they are not what this SDK reports,
     * and capturing them would flood the buffer on a chatty legacy codebase.
     */
    private function isFatal(int $type): bool
    {
        return in_array($type, [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true);
    }

    private function handleUncaughtThrowable(Throwable $throwable): void
    {
        $this->report($throwable);

        // A fatal raised while the host's handler runs is its business, not
        // ours to report on top of the exception we already captured.
        $this->fatalReported = true;

        if ($this->previousExceptionHandler !== null) {
            ($this->previousExceptionHandler)($throwable);

            return;
        }

        // With no previous handler, rethrow so PHP still prints its own
        // "Uncaught exception" report and exits non-zero, exactly as it would
        // have without this SDK installed. Merely returning here would swallow
        // that output and turn a crash into a silent exit 0. The rethrow does
        // not loop: PHP does not re-enter the exception handler for a
        // throwable raised inside it.
        throw $throwable;
    }

    private function isInternalThrowable(Throwable $throwable): bool
    {
        return str_starts_with($throwable->getFile(), dirname(__DIR__).DIRECTORY_SEPARATOR);
    }
}
