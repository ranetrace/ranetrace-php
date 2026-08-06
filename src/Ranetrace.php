<?php

declare(strict_types=1);

namespace Ranetrace\Php;

use InvalidArgumentException;
use Monolog\Level;
use Ranetrace\Php\Buffer\FileBuffer;
use Ranetrace\Php\Buffer\PauseStore;
use Ranetrace\Php\Errors\ErrorReporter;
use Ranetrace\Php\Events\EventTracker;
use Ranetrace\Php\Http\ApiClient;
use Ranetrace\Php\Http\CurlHttpClient;
use Ranetrace\Php\Http\HttpClientInterface;
use Ranetrace\Php\JavaScript\Relay;
use Ranetrace\Php\JavaScript\Snippet;
use Ranetrace\Php\Logging\RanetraceHandler;
use Ranetrace\Php\Support\FingerprintGenerator;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\SecretScrubber;
use Ranetrace\Php\Worker\Worker;
use Throwable;

/**
 * The one class a host application touches.
 *
 * Everything below it is constructor-injected and independently testable; this
 * assembles it. Two things about the assembly are deliberate.
 *
 * First, every accessor is lazy. A host that only reports exceptions should
 * never load the Monolog handler, the event tracker or the JavaScript relay, and
 * an SDK that is `require`d into every request of every page has no business
 * autoloading a dozen classes to do nothing. Lazy accessors also keep the object
 * graph honest: nothing is built until something asks for it.
 *
 * Second, `flush_on_shutdown` is on by default. Without a queue there is no
 * background process to hand a batch to, so a host with no cron entry would
 * otherwise buffer forever and drop everything at the idle TTL. Draining on
 * shutdown means telemetry leaves the process even in the simplest deployment;
 * `bin/ranetrace-flush` on a schedule is the better arrangement, and the two
 * compose safely because the buffer is locked and drained atomically.
 */
final class Ranetrace
{
    private static ?self $instance = null;

    private readonly Config $config;

    private ?InternalLogger $log = null;

    private ?FileBuffer $buffer = null;

    private ?PauseStore $pauses = null;

    private ?SecretScrubber $scrubber = null;

    private ?FingerprintGenerator $fingerprints = null;

    private ?ErrorReporter $errors = null;

    private ?EventTracker $events = null;

    private ?Relay $relay = null;

    private ?Snippet $snippet = null;

    private ?HttpClientInterface $http = null;

    /**
     * @param  array<string, mixed>  $config
     *
     * @throws InvalidArgumentException When the configuration is malformed.
     */
    public function __construct(array $config = [])
    {
        $this->config = new Config($config);

        if ($this->config->get('flush_on_shutdown') === true) {
            register_shutdown_function($this->flushQuietly(...));
        }
    }

    /**
     * Build the SDK and remember it, so framework glue and helper functions can
     * reach the same instance without threading it through every call site.
     *
     * @param  array<string, mixed>  $config
     */
    public static function init(array $config = []): self
    {
        return self::$instance = new self($config);
    }

    public static function instance(): ?self
    {
        return self::$instance;
    }

    public function config(): Config
    {
        return $this->config;
    }

    public function buffer(): FileBuffer
    {
        return $this->buffer ??= new FileBuffer($this->config, $this->log());
    }

    public function pauses(): PauseStore
    {
        return $this->pauses ??= new PauseStore($this->config);
    }

    public function events(): EventTracker
    {
        return $this->events ??= new EventTracker(
            $this->config,
            $this->buffer(),
            $this->scrubber(),
            $this->fingerprints(),
            $this->log(),
        );
    }

    public function relay(): Relay
    {
        return $this->relay ??= new Relay(
            $this->config,
            $this->buffer(),
            $this->scrubber(),
            $this->fingerprints(),
            $this->log(),
        );
    }

    /**
     * A Monolog handler that spools records into the buffer. Add it to the
     * host's logger stack to route application logs to Ranetrace.
     */
    public function monologHandler(int|string|Level|null $level = null): RanetraceHandler
    {
        return new RanetraceHandler(
            $this->config,
            $this->buffer(),
            $this->scrubber(),
            $this->log(),
            $level,
        );
    }

    /**
     * The browser capture script, ready to echo before `</body>`.
     *
     * @param  array<string, mixed>  $options  Supports `nonce` and `endpoint`.
     */
    public function javascriptSnippet(array $options = []): string
    {
        $this->snippet ??= new Snippet($this->config);

        return $this->snippet->render($options);
    }

    /**
     * Install the exception, error and fatal-shutdown handlers, chaining
     * whatever the host already registered.
     */
    public function registerErrorHandlers(): void
    {
        $this->errorReporter()->register();
    }

    public function report(Throwable $exception): void
    {
        $this->errorReporter()->report($exception);
    }

    /**
     * @param  array<string, mixed>  $properties
     */
    public function trackEvent(string $name, array $properties = [], int|string|null $userId = null, bool $validate = true): void
    {
        $this->events()->track($name, $properties, $userId, $validate);
    }

    /**
     * Drain the buffer now: one batch per type, or just the named type.
     */
    public function flush(?string $type = null): void
    {
        new Worker(
            $this->config,
            $this->buffer(),
            $this->pauses(),
            new ApiClient($this->config, $this->httpClient(), $this->log()),
            $this->log(),
        )->run($type);
    }

    /**
     * The shutdown-time flush. The worker is already built not to throw, but a
     * shutdown handler is the one place where an escaping error is unrecoverable
     * for the host, so the guarantee is restated here rather than assumed.
     */
    public function flushQuietly(?string $type = null): void
    {
        try {
            $this->flush($type);
        } catch (Throwable) {
            // A monitoring SDK must never be the reason a response fails to
            // finish.
        }
    }

    /**
     * Replace the transport. Intended for a host that already owns a configured
     * HTTP stack (an outbound proxy, mutual TLS) and for the package suite,
     * which asserts the exact wire shape against a fake.
     */
    public function withHttpClient(HttpClientInterface $http): self
    {
        $this->http = $http;

        return $this;
    }

    private function httpClient(): HttpClientInterface
    {
        return $this->http ??= new CurlHttpClient;
    }

    private function errorReporter(): ErrorReporter
    {
        return $this->errors ??= new ErrorReporter(
            $this->config,
            $this->buffer(),
            $this->scrubber(),
            $this->log(),
        );
    }

    private function log(): InternalLogger
    {
        return $this->log ??= new InternalLogger($this->config);
    }

    private function scrubber(): SecretScrubber
    {
        return $this->scrubber ??= new SecretScrubber($this->config);
    }

    private function fingerprints(): FingerprintGenerator
    {
        return $this->fingerprints ??= new FingerprintGenerator($this->config);
    }
}
