<?php

declare(strict_types=1);

namespace Ranetrace\Php\Tests\Doubles;

use Ranetrace\Php\Http\HttpClientInterface;
use Ranetrace\Php\Http\RawResponse;

/**
 * Records every request and replays queued responses. The transport seam is
 * where the wire contract is asserted, so tests hold this rather than a mock:
 * the recorded request is the exact URL, headers and body the API would see.
 */
class FakeHttpClient implements HttpClientInterface
{
    /** @var array<int, array{url: string, headers: array<string, string>, body: string, connect_timeout: int, timeout: int}> */
    public array $requests = [];

    /** @var array<int, RawResponse> */
    public array $responses = [];

    public function __construct(RawResponse ...$responses)
    {
        $this->responses = $responses;
    }

    /**
     * @param  array<string, string>  $headers  Response headers, lowercased keys.
     */
    public static function respondingWith(int $status, mixed $body = ['success' => true], array $headers = []): self
    {
        return new self(new RawResponse($status, is_string($body) ? $body : (string) json_encode($body), $headers));
    }

    public function post(string $url, array $headers, string $body, int $connectTimeout, int $timeout): RawResponse
    {
        $this->requests[] = [
            'url' => $url,
            'headers' => $headers,
            'body' => $body,
            'connect_timeout' => $connectTimeout,
            'timeout' => $timeout,
        ];

        return array_shift($this->responses) ?? new RawResponse(200, '{"success":true}');
    }

    /**
     * The decoded body of a recorded request.
     *
     * @return array<string, mixed>
     */
    public function payload(int $index = 0): array
    {
        $decoded = json_decode($this->requests[$index]['body'] ?? '', true);

        return is_array($decoded) ? $decoded : [];
    }
}
