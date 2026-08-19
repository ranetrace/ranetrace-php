<?php

declare(strict_types=1);

namespace Ranetrace\Php\Events;

use DateTimeImmutable;
use InvalidArgumentException;
use Ranetrace\Php\Buffer\BufferInterface;
use Ranetrace\Php\Config;
use Ranetrace\Php\Support\DataSanitizer;
use Ranetrace\Php\Support\FingerprintGenerator;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\ItemByteBudget;
use Ranetrace\Php\Support\SecretScrubber;
use Throwable;

/**
 * Composes tracked events and writes them to the buffer.
 *
 * Ported from `ranetrace/ranetrace-laravel`: the payload builder from
 * `src/Ranetrace.php::trackEvent()` and the naming rules plus convenience
 * methods from `src/Events/EventTracker.php`. The Laravel class is static and
 * routes through a facade; here it is an ordinary object with its collaborators
 * injected, because this SDK has no container to reach into.
 *
 * The wire shape is exactly seven keys (spec section 4) and the API does strict
 * field-set matching, so an added or dropped key rejects the whole batch. Tests
 * assert the key set, not just the values.
 *
 * Two failure postures sit side by side in {@see track()} and the split is
 * deliberate. An invalid event name is a developer mistake that is still
 * fixable, so validation runs OUTSIDE the try/catch and throws. Everything after
 * it is capture work: it is caught, logged to the internal sink and dropped,
 * because monitoring must never be the reason a checkout breaks.
 */
final class EventTracker
{
    public const string PRODUCT_ADDED_TO_CART = 'product_added_to_cart';

    public const string PRODUCT_REMOVED_FROM_CART = 'product_removed_from_cart';

    public const string CART_VIEWED = 'cart_viewed';

    public const string CHECKOUT_STARTED = 'checkout_started';

    public const string CHECKOUT_COMPLETED = 'checkout_completed';

    public const string SALE = 'sale';

    public const string USER_REGISTERED = 'user_registered';

    public const string USER_LOGGED_IN = 'user_logged_in';

    public const string USER_LOGGED_OUT = 'user_logged_out';

    public const string PAGE_VIEW = 'page_view';

    public const string SEARCH = 'search';

    public const string NEWSLETTER_SIGNUP = 'newsletter_signup';

    public const string CONTACT_FORM_SUBMITTED = 'contact_form_submitted';

    /**
     * The buffer type events are spooled under.
     */
    private const string BUFFER_TYPE = 'events';

    /**
     * Request context the event URL and the fingerprints are derived from.
     * Null means "read the live `$_SERVER`"; a host with a real request object
     * (or a test) supplies its own via {@see setServerContext()} rather than
     * having this class reach for a superglobal.
     *
     * @var array<string, mixed>|null
     */
    private ?array $server = null;

    /**
     * Console override. Null means detect from `PHP_SAPI`.
     */
    private ?bool $console = null;

    /**
     * Path segment values to redact from the event URL, as produced by
     * {@see SecretScrubber::sensitiveRouteParameterValues()}. This SDK has no
     * router to ask which segments hold a secret, so a host that knows (a
     * framework adapter) tells us; null means query-only URL scrubbing, which is
     * the correct behaviour when nobody can say.
     *
     * @var array<int, string>|null
     */
    private ?array $sensitivePathValues = null;

    private readonly ItemByteBudget $budget;

    public function __construct(
        private readonly Config $config,
        private readonly BufferInterface $buffer,
        private readonly SecretScrubber $scrubber,
        private readonly FingerprintGenerator $fingerprints,
        private readonly InternalLogger $log,
    ) {
        $this->budget = new ItemByteBudget($log);
    }

    /**
     * Whether an event name follows the naming convention: snake_case, 3 to 50
     * characters, starting with a letter, letters/digits/underscores only.
     */
    public static function validateEventName(string $eventName): bool
    {
        if (mb_strlen($eventName) < 3 || mb_strlen($eventName) > 50) {
            return false;
        }

        return preg_match('/^[a-z][a-z0-9_]*$/', $eventName) === 1;
    }

    /**
     * @throws InvalidArgumentException When the name breaks the convention.
     */
    public static function ensureValidEventName(string $eventName): void
    {
        if (! self::validateEventName($eventName)) {
            throw new InvalidArgumentException(
                "Invalid event name '{$eventName}'. Event names must be 3-50 characters, ".
                'use snake_case format (lowercase with underscores), start with a letter, '.
                'and only contain letters, numbers, and underscores.'
            );
        }
    }

    /**
     * Buffer one event.
     *
     * @param  array<array-key, mixed>  $properties  Free-form; sanitized and secret-scrubbed before it leaves the host.
     * @param  int|string|null  $userId  Explicit user id; when null the configured `user_resolver` is asked.
     * @param  bool  $validate  Pass false to accept a name that breaks the convention (see {@see customUnsafe()}).
     *
     * @throws InvalidArgumentException When $validate is true and the name breaks the convention.
     */
    public function track(string $name, array $properties = [], int|string|null $userId = null, bool $validate = true): void
    {
        if (! $this->config->enabled(self::BUFFER_TYPE)) {
            return;
        }

        if ($validate) {
            self::ensureValidEventName($name);
        }

        try {
            // The per-item byte budget runs on the finished, already scrubbed
            // item, right before it reaches the buffer. A null item was
            // irreducibly over budget and was dropped with a diagnostics entry,
            // so there is nothing left to buffer.
            $item = $this->budget->cap(self::BUFFER_TYPE, [
                'event_name' => $name,
                // The host's declared path secrets are passed through, so a URL
                // property loses its `{token}` segment the same way the event's
                // own `url` field does.
                'properties' => $this->scrubber->scrubDeep(
                    DataSanitizer::sanitizeForSerialization($properties),
                    $this->sensitivePathValues
                ),
                'user' => $this->resolveUser($userId),
                'timestamp' => (new DateTimeImmutable)->format('c'),
                'url' => $this->currentUrl(),
                'user_agent_hash' => $this->fingerprints->generateUserAgentHash($this->serverString('HTTP_USER_AGENT')),
                'session_id_hash' => $this->fingerprints->generateSessionIdHash(
                    $this->serverString('REMOTE_ADDR'),
                    $this->serverString('HTTP_USER_AGENT'),
                ),
            ]);

            if ($item === null) {
                return;
            }

            $this->buffer->addItem(self::BUFFER_TYPE, $item);
        } catch (Throwable $failure) {
            $this->log->error('Failed to track event', [
                'event_name' => $name,
                'exception' => $failure->getMessage(),
            ]);
        }
    }

    /**
     * Pin the request context instead of reading `$_SERVER`.
     *
     * @param  array<string, mixed>  $server  Superglobal-shaped request context.
     * @param  bool|null  $console  Override CLI detection; null keeps `PHP_SAPI` detection.
     */
    public function setServerContext(array $server, ?bool $console = null): void
    {
        $this->server = $server;
        $this->console = $console;
    }

    /**
     * Declare which URL path segment values hold secrets, so they are redacted
     * from the event URL. Null restores query-only scrubbing.
     *
     * @param  array<int, string>|null  $values
     */
    public function setSensitivePathValues(?array $values): void
    {
        $this->sensitivePathValues = $values;
    }

    /**
     * @param  array<array-key, mixed>  $additionalProperties  Merged over the base properties, so a caller can override any of them.
     */
    public function productAddedToCart(
        string $productId,
        string $productName,
        float $price,
        int $quantity = 1,
        ?string $category = null,
        array $additionalProperties = [],
    ): void {
        $properties = array_merge([
            'product_id' => $productId,
            'product_name' => $productName,
            'price' => $price,
            'quantity' => $quantity,
            'total_value' => $price * $quantity,
        ], $additionalProperties);

        // Set AFTER the merge on purpose: the named argument is the more
        // specific statement of intent, so it wins over a `category` smuggled in
        // through the additional properties.
        if ($category !== null && $category !== '') {
            $properties['category'] = $category;
        }

        $this->track(self::PRODUCT_ADDED_TO_CART, $properties);
    }

    /**
     * @param  array<array-key, mixed>  $products
     * @param  array<array-key, mixed>  $additionalProperties  Merged over the base properties, so a caller can override any of them.
     */
    public function sale(
        string $orderId,
        float $totalAmount,
        array $products = [],
        ?string $currency = 'USD',
        array $additionalProperties = [],
    ): void {
        $this->track(self::SALE, array_merge([
            'order_id' => $orderId,
            'total_amount' => $totalAmount,
            'currency' => $currency,
            'products' => $products,
            'product_count' => count($products),
        ], $additionalProperties));
    }

    /**
     * @param  array<array-key, mixed>  $additionalProperties  Sent verbatim; this event has no base properties.
     */
    public function userRegistered(int|string|null $userId = null, array $additionalProperties = []): void
    {
        $this->track(self::USER_REGISTERED, $additionalProperties, $userId);
    }

    /**
     * @param  array<array-key, mixed>  $additionalProperties  Sent verbatim; this event has no base properties.
     */
    public function userLoggedIn(int|string|null $userId = null, array $additionalProperties = []): void
    {
        $this->track(self::USER_LOGGED_IN, $additionalProperties, $userId);
    }

    /**
     * @param  array<array-key, mixed>  $additionalProperties  Merged over `page_name`.
     */
    public function pageView(string $pageName, array $additionalProperties = []): void
    {
        $this->track(self::PAGE_VIEW, array_merge([
            'page_name' => $pageName,
        ], $additionalProperties));
    }

    /**
     * @param  array<array-key, mixed>  $properties
     *
     * @throws InvalidArgumentException When the name breaks the convention.
     */
    public function custom(string $eventName, array $properties = [], int|string|null $userId = null): void
    {
        self::ensureValidEventName($eventName);

        $this->track($eventName, $properties, $userId);
    }

    /**
     * Track an event whose name breaks the naming convention. Only reach for
     * this when an existing external name has to be preserved: unconventional
     * names make the events dashboard harder to read for everyone after you.
     *
     * @param  array<array-key, mixed>  $properties
     */
    public function customUnsafe(string $eventName, array $properties = [], int|string|null $userId = null): void
    {
        $this->track($eventName, $properties, $userId, false);
    }

    /**
     * The event's `user` field: the explicit id when given, else whatever the
     * configured resolver reports, else null. Only the id travels; events carry
     * no email.
     *
     * @return array{id: int|string}|null
     */
    private function resolveUser(int|string|null $userId): ?array
    {
        if ($userId !== null) {
            return ['id' => $userId];
        }

        $resolver = $this->config->get('user_resolver');

        if (! is_callable($resolver)) {
            return null;
        }

        $resolved = $resolver();

        if (! is_array($resolved) || ! isset($resolved['id'])) {
            return null;
        }

        $id = $resolved['id'];

        return is_int($id) || is_string($id) ? ['id' => $id] : null;
    }

    /**
     * The scrubbed URL of the current request, or null when there is no request:
     * a CLI process has no URL to report, and neither does a web context that
     * did not tell us its host.
     */
    private function currentUrl(): ?string
    {
        if ($this->isConsole()) {
            return null;
        }

        $host = $this->serverString('HTTP_HOST') ?? $this->serverString('SERVER_NAME');

        if ($host === null) {
            return null;
        }

        $uri = $this->serverString('REQUEST_URI') ?? '/';

        return $this->scrubber->scrubUrlPath(
            $this->scrubber->scrubUrl($this->scheme().'://'.$host.$uri),
            $this->sensitivePathValues,
        );
    }

    /**
     * Request scheme, read in the order a reverse proxy is least likely to lie:
     * an explicit `HTTPS` flag, then `REQUEST_SCHEME`, then the port.
     */
    private function scheme(): string
    {
        $https = $this->serverString('HTTPS');

        if ($https !== null && mb_strtolower($https) !== 'off') {
            return 'https';
        }

        $scheme = $this->serverString('REQUEST_SCHEME');

        if ($scheme !== null) {
            return mb_strtolower($scheme);
        }

        return $this->serverString('SERVER_PORT') === '443' ? 'https' : 'http';
    }

    private function isConsole(): bool
    {
        return $this->console ?? (PHP_SAPI === 'cli');
    }

    /**
     * One request-context value as a non-empty string, or null.
     */
    private function serverString(string $key): ?string
    {
        $value = $this->serverContext()[$key] ?? null;

        if (! is_scalar($value)) {
            return null;
        }

        $value = (string) $value;

        return $value === '' ? null : $value;
    }

    /**
     * @return array<string, mixed>
     */
    private function serverContext(): array
    {
        return $this->server ?? $_SERVER;
    }
}
