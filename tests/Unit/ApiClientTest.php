<?php

declare(strict_types=1);

use Ranetrace\Php\Http\ApiClient;
use Ranetrace\Php\Http\RawResponse;
use Ranetrace\Php\Support\InternalLogger;
use Ranetrace\Php\Tests\Doubles\FakeHttpClient;

function apiClient(FakeHttpClient $http, array $overrides = []): ApiClient
{
    $config = testConfig(array_replace([
        'buffer_path' => tempDirectory(),
        'internal_logging' => ['enabled' => false],
    ], $overrides));

    return new ApiClient($config, $http, new InternalLogger($config));
}

it('sends exactly the five contracted headers', function (): void {
    $http = FakeHttpClient::respondingWith(200);

    apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, [['message' => 'boom']]);

    expect($http->requests[0]['headers'])->toBe([
        'Authorization' => 'Bearer test-api-key-12345',
        'User-Agent' => 'Ranetrace-PHP/Errors/1.0',
        'Content-Type' => 'application/json',
        'Accept' => 'application/json',
        'Ranetrace-API-Version' => '1.0',
    ]);
});

it('posts to the base url plus the endpoint path', function (): void {
    $http = FakeHttpClient::respondingWith(200);

    apiClient($http, ['base_url' => 'https://api.example.test/v1/'])
        ->sendBatch('/events/store', 'events', 'Ranetrace-PHP/Events/1.0', 10, [['event_name' => 'sale']]);

    expect($http->requests[0]['url'])->toBe('https://api.example.test/v1/events/store');
});

it('defaults to the production api base url', function (): void {
    $http = FakeHttpClient::respondingWith(200);

    apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, [['message' => 'boom']]);

    expect($http->requests[0]['url'])->toBe('https://api.ranetrace.com/v1/errors/store');
});

it('wraps the items under the feature key as the only top level key', function (): void {
    $http = FakeHttpClient::respondingWith(200);

    apiClient($http)->sendBatch('/logs/store', 'logs', 'Ranetrace-PHP/Logs/1.0', 10, [
        ['message' => 'first'],
        ['message' => 'second'],
    ]);

    $payload = $http->payload();

    expect(array_keys($payload))->toBe(['logs'])
        ->and($payload['logs'])->toBe([['message' => 'first'], ['message' => 'second']]);
});

it('reindexes a sparse item list so the body is a json array', function (): void {
    $http = FakeHttpClient::respondingWith(200);

    apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, [
        3 => ['message' => 'kept'],
    ]);

    expect($http->requests[0]['body'])->toBe('{"errors":[{"message":"kept"}]}');
});

it('passes the connect timeout and the per feature timeout through', function (): void {
    $http = FakeHttpClient::respondingWith(200);

    apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 25, [['message' => 'boom']]);

    expect($http->requests[0]['connect_timeout'])->toBe(5)
        ->and($http->requests[0]['timeout'])->toBe(25);
});

it('falls back to a ten second timeout when a non positive one is given', function (): void {
    $http = FakeHttpClient::respondingWith(200);

    apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 0, [['message' => 'boom']]);

    expect($http->requests[0]['timeout'])->toBe(10);
});

it('refuses to send without an api key', function (): void {
    $http = FakeHttpClient::respondingWith(200);

    $result = apiClient($http, ['key' => ''])
        ->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, [['message' => 'boom']]);

    expect($result['status'])->toBe(0)
        ->and($result['success'])->toBeFalse()
        ->and($result['error'])->toBe('API key not configured')
        ->and($http->requests)->toBe([]);
});

it('refuses to send an empty batch', function (): void {
    $http = FakeHttpClient::respondingWith(200);

    $result = apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, []);

    expect($result['status'])->toBe(0)
        ->and($result['error'])->toBe('Empty batch provided')
        ->and($http->requests)->toBe([]);
});

it('normalises a successful response', function (): void {
    $http = FakeHttpClient::respondingWith(200, ['items' => ['received' => 2, 'processed' => 2]]);

    $result = apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, [['message' => 'boom']]);

    expect($result)->toBe([
        'status' => 200,
        'success' => true,
        'data' => ['items' => ['received' => 2, 'processed' => 2]],
        'headers' => ['retry-after' => ''],
        'error' => null,
    ]);
});

it('reports an unparseable success body as an invalid response format', function (): void {
    $http = new FakeHttpClient(new RawResponse(200, 'not json at all'));

    $result = apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, [['message' => 'boom']]);

    expect($result['success'])->toBeFalse()
        ->and($result['data'])->toBe([])
        ->and($result['error'])->toBe('Invalid response format');
});

it('keeps retry-after as an empty string when the header is absent', function (): void {
    $http = FakeHttpClient::respondingWith(429, ['error' => ['message' => 'Too Many Requests']]);

    $result = apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, [['message' => 'boom']]);

    expect($result['status'])->toBe(429)
        ->and($result['success'])->toBeFalse()
        ->and($result['headers']['retry-after'])->toBe('');
});

it('surfaces the retry-after header when the api sends one', function (): void {
    $http = new FakeHttpClient(new RawResponse(429, '{}', ['retry-after' => '120']));

    $result = apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, [['message' => 'boom']]);

    expect($result['headers']['retry-after'])->toBe('120');
});

it('turns a transport failure into a status zero result', function (): void {
    $http = new FakeHttpClient(RawResponse::transportFailure('Could not resolve host'));

    $result = apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, [['message' => 'boom']]);

    expect($result['status'])->toBe(0)
        ->and($result['success'])->toBeFalse()
        ->and($result['error'])->toBe('Could not resolve host')
        ->and($result['headers']['retry-after'])->toBeNull();
});

it('never lets a throwing transport escape', function (): void {
    $http = new class extends FakeHttpClient
    {
        public function post(string $url, array $headers, string $body, int $connectTimeout, int $timeout): RawResponse
        {
            throw new RuntimeException('transport exploded');
        }
    };

    $result = apiClient($http)->sendBatch('/errors/store', 'errors', 'Ranetrace-PHP/Errors/1.0', 10, [['message' => 'boom']]);

    expect($result['status'])->toBe(0)
        ->and($result['error'])->toBe('transport exploded');
});

it('reads a raw response header case insensitively', function (): void {
    $response = new RawResponse(429, '', ['retry-after' => '30']);

    expect($response->header('Retry-After'))->toBe('30')
        ->and($response->header('X-Missing'))->toBeNull();
});
