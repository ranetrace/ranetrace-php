<?php

declare(strict_types=1);

use Ranetrace\Php\Buffer\FileBuffer;
use Ranetrace\Php\Buffer\PauseStore;
use Ranetrace\Php\Config;
use Ranetrace\Php\Http\RawResponse;
use Ranetrace\Php\Ranetrace;
use Ranetrace\Php\Tests\Doubles\FakeHttpClient;

/**
 * A facade with the shutdown flush disabled, so a test never leaves a drain
 * queued against a temp directory that afterEach has already removed.
 */
function ranetraceFacade(string $directory, array $overrides = []): Ranetrace
{
    return new Ranetrace(array_replace_recursive([
        'key' => 'test-api-key-12345',
        'buffer_path' => $directory,
        'flush_on_shutdown' => false,
        'internal_logging' => ['enabled' => false],
    ], $overrides));
}

it('resolves its configuration through Config', function (): void {
    $directory = tempDirectory();
    $ranetrace = ranetraceFacade($directory, ['errors' => ['timeout' => 30]]);

    expect($ranetrace->config())->toBeInstanceOf(Config::class)
        ->and($ranetrace->config()->key())->toBe('test-api-key-12345')
        ->and($ranetrace->config()->get('buffer_path'))->toBe($directory)
        ->and($ranetrace->config()->get('errors.timeout'))->toBe(30)
        ->and($ranetrace->config()->get('batch.max_buffer_size'))->toBe(5000);
});

it('rejects a malformed configuration loudly', function (): void {
    expect(fn (): Ranetrace => new Ranetrace(['key' => 123]))
        ->toThrow(InvalidArgumentException::class);
});

it('builds the buffer and the pause store lazily and once', function (): void {
    $ranetrace = ranetraceFacade(tempDirectory());

    expect($ranetrace->buffer())->toBeInstanceOf(FileBuffer::class)
        ->and($ranetrace->buffer())->toBe($ranetrace->buffer())
        ->and($ranetrace->pauses())->toBeInstanceOf(PauseStore::class)
        ->and($ranetrace->pauses())->toBe($ranetrace->pauses());
});

it('points the buffer and the pause store at the same directory', function (): void {
    $directory = tempDirectory();
    $ranetrace = ranetraceFacade($directory);

    $ranetrace->buffer()->addItem('errors', ['message' => 'boom']);
    $ranetrace->pauses()->pauseFeature('events', 900, '429');

    expect(is_file($directory.'/errors.json'))->toBeTrue()
        ->and(is_file($directory.'/pauses.json'))->toBeTrue();
});

it('remembers the instance init built', function (): void {
    $directory = tempDirectory();

    $first = Ranetrace::init(['key' => 'k', 'buffer_path' => $directory, 'flush_on_shutdown' => false]);

    expect(Ranetrace::instance())->toBe($first);

    $second = Ranetrace::init(['key' => 'k2', 'buffer_path' => $directory, 'flush_on_shutdown' => false]);

    expect(Ranetrace::instance())->toBe($second)
        ->and(Ranetrace::instance()?->config()->key())->toBe('k2');
});

it('drains a seeded buffer through the injected transport', function (): void {
    $directory = tempDirectory();
    $http = FakeHttpClient::respondingWith(200);

    $ranetrace = ranetraceFacade($directory)->withHttpClient($http);
    $ranetrace->buffer()->addItem('errors', ['message' => 'boom']);

    $ranetrace->flush();

    expect($http->requests)->toHaveCount(1)
        ->and($http->requests[0]['url'])->toBe('https://api.ranetrace.com/v1/errors/store')
        ->and($http->payload())->toBe(['errors' => [['message' => 'boom']]])
        ->and($ranetrace->buffer()->count('errors'))->toBe(0);
});

it('drains only the named type', function (): void {
    $directory = tempDirectory();
    $http = FakeHttpClient::respondingWith(200);

    $ranetrace = ranetraceFacade($directory)->withHttpClient($http);
    $ranetrace->buffer()->addItem('errors', ['message' => 'boom']);
    $ranetrace->buffer()->addItem('events', ['event_name' => 'sale']);

    $ranetrace->flush('events');

    expect($http->requests)->toHaveCount(1)
        ->and($ranetrace->buffer()->count('errors'))->toBe(1)
        ->and($ranetrace->buffer()->count('events'))->toBe(0);
});

it('leaves the items buffered and pauses when the flush fails', function (): void {
    $directory = tempDirectory();
    $http = new FakeHttpClient(RawResponse::transportFailure('Connection refused'));

    $ranetrace = ranetraceFacade($directory)->withHttpClient($http);
    $ranetrace->buffer()->addItem('errors', ['message' => 'boom']);

    $ranetrace->flush();

    expect($ranetrace->buffer()->count('errors'))->toBe(1)
        ->and($ranetrace->pauses()->isFeaturePaused('errors'))->toBeTrue();
});

it('respects a pause set before the flush', function (): void {
    $directory = tempDirectory();
    $http = FakeHttpClient::respondingWith(200);

    $ranetrace = ranetraceFacade($directory)->withHttpClient($http);
    $ranetrace->buffer()->addItem('errors', ['message' => 'boom']);
    $ranetrace->pauses()->pauseGlobal(900, '401');

    $ranetrace->flush();

    expect($http->requests)->toBe([])
        ->and($ranetrace->buffer()->count('errors'))->toBe(1);
});

it('never lets a shutdown flush throw', function (): void {
    $ranetrace = ranetraceFacade('/proc/definitely-not-writable/ranetrace');

    $ranetrace->flushQuietly();

    expect($ranetrace->buffer()->count('errors'))->toBe(0);
});

it('contains a transport that throws instead of surfacing it', function (): void {
    $http = new class extends FakeHttpClient
    {
        public function post(string $url, array $headers, string $body, int $connectTimeout, int $timeout): RawResponse
        {
            throw new RuntimeException('transport exploded');
        }
    };

    $ranetrace = ranetraceFacade(tempDirectory())->withHttpClient($http);
    $ranetrace->buffer()->addItem('errors', ['message' => 'boom']);

    $ranetrace->flushQuietly();

    expect($ranetrace->buffer()->count('errors'))->toBe(1)
        ->and($ranetrace->pauses()->isFeaturePaused('errors'))->toBeTrue();
});

it('does nothing on flush when the buffer is empty', function (): void {
    $http = FakeHttpClient::respondingWith(200);

    ranetraceFacade(tempDirectory())->withHttpClient($http)->flush();

    expect($http->requests)->toBe([]);
});
