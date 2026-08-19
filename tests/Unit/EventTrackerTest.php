<?php

declare(strict_types=1);

use Ranetrace\Php\Events\EventTracker;
use Ranetrace\Php\Support\FingerprintGenerator;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Support\ItemByteBudget;
use Ranetrace\Php\Support\SecretScrubber;
use Ranetrace\Php\Tests\Doubles\ArrayBuffer;

/**
 * The exact key set the events endpoint accepts. An extra or missing key here
 * is a 422 on the whole batch in production, so the tests below assert the key
 * set itself, not only the values.
 *
 * @var array<int, string>
 */
const EVENT_KEYS = [
    'event_name',
    'properties',
    'user',
    'timestamp',
    'url',
    'user_agent_hash',
    'session_id_hash',
];

/**
 * @param  array<string, mixed>  $overrides
 */
function eventTracker(ArrayBuffer $buffer, array $overrides = []): EventTracker
{
    $config = testConfig(array_replace([
        'internal_logging' => ['enabled' => false],
    ], $overrides));

    return new EventTracker(
        $config,
        $buffer,
        new SecretScrubber($config, new InternalLogger($config)),
        new FingerprintGenerator($config),
        new InternalLogger($config),
    );
}

/**
 * @return array<string, mixed>
 */
function firstEvent(ArrayBuffer $buffer): array
{
    return $buffer->payloads('events')[0];
}

test('it buffers an event under the events type with exactly the seven wire keys', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->track('checkout_started', ['plan' => 'pro']);

    expect($buffer->count('events'))->toBe(1)
        ->and(array_keys(firstEvent($buffer)))->toBe(EVENT_KEYS);
});

test('it records the event name and an iso 8601 timestamp', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->track('checkout_started');

    $event = firstEvent($buffer);

    expect($event['event_name'])->toBe('checkout_started')
        ->and($event['timestamp'])->toMatch('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/');
});

test('it defaults properties to an empty array', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->track('cart_viewed');

    expect(firstEvent($buffer)['properties'])->toBe([]);
});

test('it sanitizes and scrubs event properties', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->track('checkout_started', [
        'api_token' => 'super-secret',
        'callback' => fn (): string => 'nope',
        'nested' => ['password' => 'hunter2', 'plan' => 'pro'],
        'endpoint' => 'https://api.test/v1?api_key=leaked&page=2',
    ]);

    expect(firstEvent($buffer)['properties'])->toBe([
        'api_token' => '[REDACTED]',
        'callback' => '[Closure]',
        'nested' => ['password' => '[REDACTED]', 'plan' => 'pro'],
        'endpoint' => 'https://api.test/v1?api_key=[REDACTED]&page=2',
    ]);
});

test('an explicit user id wins over the configured resolver', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer, ['user_resolver' => fn (): array => ['id' => 'resolved', 'email' => 'a@b.test']])
        ->track('user_logged_in', [], 42);

    expect(firstEvent($buffer)['user'])->toBe(['id' => 42]);
});

test('it falls back to the configured user resolver and keeps only the id', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer, ['user_resolver' => fn (): array => ['id' => 7, 'email' => 'a@b.test']])
        ->track('user_logged_in');

    expect(firstEvent($buffer)['user'])->toBe(['id' => 7]);
});

test('the user is null when nothing resolves one', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->track('page_view');

    expect(firstEvent($buffer)['user'])->toBeNull();

    $other = new ArrayBuffer;

    eventTracker($other, ['user_resolver' => fn (): ?array => null])->track('page_view');

    expect(firstEvent($other)['user'])->toBeNull();
});

test('the url is null under cli because a console process has no url', function (): void {
    $buffer = new ArrayBuffer;

    $tracker = eventTracker($buffer);
    $tracker->setServerContext(['HTTP_HOST' => 'app.test', 'REQUEST_URI' => '/checkout'], console: true);
    $tracker->track('checkout_started');

    expect(firstEvent($buffer)['url'])->toBeNull();
});

test('it builds the url from the injected server context and scrubs its query', function (): void {
    $buffer = new ArrayBuffer;

    $tracker = eventTracker($buffer);
    $tracker->setServerContext([
        'HTTPS' => 'on',
        'HTTP_HOST' => 'app.test',
        'REQUEST_URI' => '/checkout?token=abc123&page=2',
    ], console: false);
    $tracker->track('checkout_started');

    expect(firstEvent($buffer)['url'])->toBe('https://app.test/checkout?token=[REDACTED]&page=2');
});

test('it falls back to http and a root path when the context says little', function (): void {
    $buffer = new ArrayBuffer;

    $tracker = eventTracker($buffer);
    $tracker->setServerContext(['SERVER_NAME' => 'app.test'], console: false);
    $tracker->track('checkout_started');

    expect(firstEvent($buffer)['url'])->toBe('http://app.test/');
});

test('the url is null in a web context that names no host', function (): void {
    $buffer = new ArrayBuffer;

    $tracker = eventTracker($buffer);
    $tracker->setServerContext(['REQUEST_URI' => '/checkout'], console: false);
    $tracker->track('checkout_started');

    expect(firstEvent($buffer)['url'])->toBeNull();
});

test('it redacts host declared sensitive path segments from the url', function (): void {
    $buffer = new ArrayBuffer;

    $tracker = eventTracker($buffer);
    $tracker->setServerContext(['HTTP_HOST' => 'app.test', 'REQUEST_URI' => '/reset/abc123'], console: false);
    $tracker->setSensitivePathValues(['abc123']);
    $tracker->track('page_view');

    expect(firstEvent($buffer)['url'])->toBe('http://app.test/reset/[REDACTED]');
});

test('it hashes the user agent and the session fingerprint rather than sending them raw', function (): void {
    $buffer = new ArrayBuffer;
    $config = testConfig(['internal_logging' => ['enabled' => false]]);

    $tracker = eventTracker($buffer);
    $tracker->setServerContext([
        'HTTP_HOST' => 'app.test',
        'REQUEST_URI' => '/',
        'HTTP_USER_AGENT' => 'Test Browser',
        'REMOTE_ADDR' => '203.0.113.10',
    ], console: false);
    $tracker->track('page_view');

    $fingerprints = new FingerprintGenerator($config);
    $event = firstEvent($buffer);

    expect($event['user_agent_hash'])->toBe($fingerprints->generateUserAgentHash('Test Browser'))
        ->and($event['session_id_hash'])->toBe($fingerprints->generateSessionIdHash('203.0.113.10', 'Test Browser'))
        ->and($event['user_agent_hash'])->not->toContain('Test Browser')
        ->and($event['session_id_hash'])->toHaveLength(64);
});

test('the user agent hash is empty when the request carried none', function (): void {
    $buffer = new ArrayBuffer;

    $tracker = eventTracker($buffer);
    $tracker->setServerContext(['HTTP_HOST' => 'app.test', 'REQUEST_URI' => '/'], console: false);
    $tracker->track('page_view');

    expect(firstEvent($buffer)['user_agent_hash'])->toBe('');
});

test('an invalid event name throws loudly because it is a developer mistake', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->track('Not Valid');
})->throws(
    InvalidArgumentException::class,
    "Invalid event name 'Not Valid'. Event names must be 3-50 characters, use snake_case format (lowercase with underscores), start with a letter, and only contain letters, numbers, and underscores."
);

test('event name validation accepts and rejects the documented shapes', function (string $name, bool $valid): void {
    expect(EventTracker::validateEventName($name))->toBe($valid);
})->with([
    ['sale', true],
    ['product_added_to_cart', true],
    ['a1_b2', true],
    ['ab', false],
    [str_repeat('a', 51), false],
    [str_repeat('a', 50), true],
    ['Sale', false],
    ['1sale', false],
    ['_sale', false],
    ['sale-now', false],
    ['sale now', false],
]);

test('validation can be bypassed for a name that must be preserved', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->track('Legacy Name', [], null, false);

    expect(firstEvent($buffer)['event_name'])->toBe('Legacy Name');
});

test('an invalid name does not throw while events are disabled, because the gate runs first', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer, ['events' => ['enabled' => false]])->track('Not Valid');

    expect($buffer->count('events'))->toBe(0);
});

test('it buffers nothing when the feature or the sdk is off or the key is missing', function (array $overrides): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer, $overrides)->track('page_view');

    expect($buffer->count('events'))->toBe(0);
})->with([
    'events disabled' => [['events' => ['enabled' => false]]],
    'sdk disabled' => [['enabled' => false]],
    'no api key' => [['key' => '']],
]);

test('a rejected buffer write is a silent drop, never an exception into the host', function (): void {
    $buffer = new ArrayBuffer;
    $buffer->rejectWrites = true;

    eventTracker($buffer)->track('page_view');

    expect($buffer->count('events'))->toBe(0);
});

test('a failure while building the payload is swallowed', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer, [
        'user_resolver' => function (): array {
            throw new RuntimeException('resolver exploded');
        },
    ])->track('page_view');

    expect($buffer->count('events'))->toBe(0);
});

test('the standard event name constants are the thirteen agreed names', function (): void {
    expect([
        EventTracker::PRODUCT_ADDED_TO_CART,
        EventTracker::PRODUCT_REMOVED_FROM_CART,
        EventTracker::CART_VIEWED,
        EventTracker::CHECKOUT_STARTED,
        EventTracker::CHECKOUT_COMPLETED,
        EventTracker::SALE,
        EventTracker::USER_REGISTERED,
        EventTracker::USER_LOGGED_IN,
        EventTracker::USER_LOGGED_OUT,
        EventTracker::PAGE_VIEW,
        EventTracker::SEARCH,
        EventTracker::NEWSLETTER_SIGNUP,
        EventTracker::CONTACT_FORM_SUBMITTED,
    ])->toBe([
        'product_added_to_cart',
        'product_removed_from_cart',
        'cart_viewed',
        'checkout_started',
        'checkout_completed',
        'sale',
        'user_registered',
        'user_logged_in',
        'user_logged_out',
        'page_view',
        'search',
        'newsletter_signup',
        'contact_form_submitted',
    ]);
});

test('productAddedToCart sends the documented property keys and derives the total value', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->productAddedToCart('sku-1', 'Blue Mug', 12.5, 3);

    $event = firstEvent($buffer);

    expect($event['event_name'])->toBe('product_added_to_cart')
        ->and($event['properties'])->toBe([
            'product_id' => 'sku-1',
            'product_name' => 'Blue Mug',
            'price' => 12.5,
            'quantity' => 3,
            'total_value' => 37.5,
        ]);
});

test('productAddedToCart additional properties override the base properties', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->productAddedToCart('sku-1', 'Blue Mug', 10.0, 2, null, [
        'total_value' => 999.0,
        'source' => 'quick-add',
    ]);

    expect(firstEvent($buffer)['properties'])->toBe([
        'product_id' => 'sku-1',
        'product_name' => 'Blue Mug',
        'price' => 10.0,
        'quantity' => 2,
        'total_value' => 999.0,
        'source' => 'quick-add',
    ]);
});

test('productAddedToCart sets the category after the merge so the named argument wins', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->productAddedToCart('sku-1', 'Blue Mug', 10.0, 1, 'drinkware', [
        'category' => 'smuggled',
    ]);

    expect(firstEvent($buffer)['properties']['category'])->toBe('drinkware');
});

test('productAddedToCart omits the category key entirely when it is null or empty', function (?string $category): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->productAddedToCart('sku-1', 'Blue Mug', 10.0, 1, $category);

    expect(firstEvent($buffer)['properties'])->not->toHaveKey('category');
})->with([
    'null' => [null],
    'empty string' => [''],
]);

test('sale sends the documented property keys and counts the products', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->sale('order-9', 99.95, [['sku' => 'a'], ['sku' => 'b']], 'EUR');

    $event = firstEvent($buffer);

    expect($event['event_name'])->toBe('sale')
        ->and($event['properties'])->toBe([
            'order_id' => 'order-9',
            'total_amount' => 99.95,
            'currency' => 'EUR',
            'products' => [['sku' => 'a'], ['sku' => 'b']],
            'product_count' => 2,
        ]);
});

test('sale defaults the currency to usd and additional properties override the base', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->sale('order-9', 10.0, [], null, ['product_count' => 42]);

    $properties = firstEvent($buffer)['properties'];

    expect($properties['currency'])->toBeNull()
        ->and($properties['product_count'])->toBe(42);

    $other = new ArrayBuffer;

    eventTracker($other)->sale('order-9', 10.0);

    expect(firstEvent($other)['properties']['currency'])->toBe('USD');
});

test('userRegistered and userLoggedIn pass their properties through verbatim and set the user id', function (): void {
    $buffer = new ArrayBuffer;
    $tracker = eventTracker($buffer);

    $tracker->userRegistered(11, ['plan' => 'pro']);
    $tracker->userLoggedIn('user-12', ['via' => 'sso']);

    $events = $buffer->payloads('events');

    expect($events[0]['event_name'])->toBe('user_registered')
        ->and($events[0]['properties'])->toBe(['plan' => 'pro'])
        ->and($events[0]['user'])->toBe(['id' => 11])
        ->and($events[1]['event_name'])->toBe('user_logged_in')
        ->and($events[1]['properties'])->toBe(['via' => 'sso'])
        ->and($events[1]['user'])->toBe(['id' => 'user-12']);
});

test('pageView merges additional properties over the page name', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->pageView('pricing', ['variant' => 'b']);

    $event = firstEvent($buffer);

    expect($event['event_name'])->toBe('page_view')
        ->and($event['properties'])->toBe(['page_name' => 'pricing', 'variant' => 'b']);
});

test('custom validates the event name', function (): void {
    eventTracker(new ArrayBuffer)->custom('NOT VALID');
})->throws(InvalidArgumentException::class);

test('customUnsafe skips validation', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->customUnsafe('NOT VALID', ['a' => 1], 5);

    $event = firstEvent($buffer);

    expect($event['event_name'])->toBe('NOT VALID')
        ->and($event['properties'])->toBe(['a' => 1])
        ->and($event['user'])->toBe(['id' => 5]);
});

test('an event over the per-item byte budget has its properties replaced, never its top level', function (): void {
    $buffer = new ArrayBuffer;

    eventTracker($buffer)->track('checkout_started', ['blob' => str_repeat('p', 100_000)]);

    $event = firstEvent($buffer);

    expect(array_keys($event))->toBe(EVENT_KEYS)
        ->and($event)->not->toHaveKey('_truncated')
        ->and($event['properties'])->toBe(['_truncated' => 'Field exceeded the per-item budget and was removed'])
        ->and(mb_strlen((string) json_encode($event), '8bit'))->toBeLessThanOrEqual(ItemByteBudget::MAX_ITEM_BYTES);
});
