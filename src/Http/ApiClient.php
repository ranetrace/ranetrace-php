<?php

declare(strict_types=1);

namespace Ranetrace\Php\Http;

use Ranetrace\Php\Config;
use Ranetrace\Php\Support\InternalLogger;
use Throwable;

/**
 * Speaks the Ranetrace batch API: five headers, one wrapper key, one POST.
 * The heartbeat is the one request beside the batches, see {@see sendHeartbeat()}.
 *
 * Ported from `ranetrace/ranetrace-laravel` (`src/Services/RanetraceApiClient.php`).
 * The wire contract is strict on the server side, so the details here are not
 * stylistic: exactly the five headers below, a body whose single top-level key
 * is the feature's wrapper key, and a normalised result array the worker can
 * pattern-match on. A batch that gets any of it wrong is rejected whole.
 *
 * The normalised result always carries the same five keys, including
 * `headers['retry-after']`. That key is `''` (not null) when a real response
 * omitted the header, mirroring the Laravel client and preserving the gotcha the
 * worker has to defend against: `(int) '' === 0`, so a bare cast would produce a
 * zero-second rate-limit pause. The floor lives in `Worker\Worker`.
 */
final class ApiClient
{
    /**
     * Connection-phase timeout in seconds. Deliberately much shorter than the
     * total timeout: an unreachable host should fail fast rather than hold a
     * request-cycle flush open for the full window.
     */
    private const int CONNECT_TIMEOUT = 5;

    private const string API_VERSION = '1.0';

    public function __construct(
        private readonly Config $config,
        private readonly HttpClientInterface $http,
        private readonly InternalLogger $log,
    ) {}

    /**
     * POST one batch to a feature's store endpoint.
     *
     * @param  string  $path  Endpoint path, e.g. `/errors/store`.
     * @param  string  $wrapperKey  The single top-level body key, e.g. `errors`.
     * @param  string  $userAgent  Per-feature agent, e.g. `Ranetrace-PHP/Errors/1.0`.
     * @param  int  $timeout  Total request timeout in seconds.
     * @param  array<int, array<string, mixed>>  $items
     * @return array{status: int, success: bool, data: array<string, mixed>, headers: array{retry-after: ?string}, error: ?string}
     */
    public function sendBatch(string $path, string $wrapperKey, string $userAgent, int $timeout, array $items): array
    {
        $key = $this->config->key();

        if ($key === '') {
            return self::errorResult('API key not configured');
        }

        if ($items === []) {
            return self::errorResult('Empty batch provided');
        }

        $body = json_encode([$wrapperKey => array_values($items)]);

        if (! is_string($body)) {
            return self::errorResult('Failed to encode batch payload');
        }

        $result = $this->post($path, $key, $userAgent, $body, $timeout);

        if ($result['status'] !== 0) {
            $this->log->debug('Batch request completed', [
                'path' => $path,
                'status' => $result['status'],
                'items' => count($items),
            ]);
        }

        return $result;
    }

    /**
     * POST one heartbeat: the same five headers as a batch, and a body that is
     * the heartbeat's two fields with no wrapper key.
     *
     * The result has the shape of a batch result so a caller reads both alike,
     * but nothing in it is a decision: a heartbeat has no items to keep or
     * drop, and its answer pauses nothing. See `contract/heartbeat.json`.
     *
     * @return array{status: int, success: bool, data: array<string, mixed>, headers: array{retry-after: ?string}, error: ?string}
     */
    public function sendHeartbeat(Heartbeat $heartbeat): array
    {
        $key = $this->config->key();

        if ($key === '') {
            return self::errorResult('API key not configured');
        }

        $body = json_encode($heartbeat->body());

        if (! is_string($body)) {
            return self::errorResult('Failed to encode heartbeat payload');
        }

        return $this->post(Heartbeat::PATH, $key, $heartbeat->userAgent(), $body, Heartbeat::TIMEOUT_SECONDS);
    }

    /**
     * @return array{status: int, success: bool, data: array<string, mixed>, headers: array{retry-after: ?string}, error: ?string}
     */
    private static function normalise(RawResponse $response): array
    {
        $decoded = json_decode($response->body, true);
        $isValidData = is_array($decoded);
        $isSuccessful = $response->status >= 200 && $response->status < 300;

        return [
            'status' => $response->status,
            'success' => $isSuccessful && $isValidData,
            'data' => $isValidData ? $decoded : [],
            'headers' => ['retry-after' => $response->headers['retry-after'] ?? ''],
            'error' => $isSuccessful && ! $isValidData ? 'Invalid response format' : null,
        ];
    }

    /**
     * A failure that never reached an HTTP status: a missing key, an empty
     * batch, or a dead connection. Status 0 is what the worker's response matrix
     * treats as "re-buffer and back off".
     *
     * @return array{status: int, success: bool, data: array<string, mixed>, headers: array{retry-after: ?string}, error: ?string}
     */
    private static function errorResult(string $message): array
    {
        return [
            'status' => 0,
            'success' => false,
            'data' => [],
            'headers' => ['retry-after' => null],
            'error' => $message,
        ];
    }

    /**
     * One POST, normalised. A request that reached no HTTP status comes back
     * as status 0 and never as an exception.
     *
     * @return array{status: int, success: bool, data: array<string, mixed>, headers: array{retry-after: ?string}, error: ?string}
     */
    private function post(string $path, string $key, string $userAgent, string $body, int $timeout): array
    {
        try {
            $response = $this->http->post(
                $this->url($path),
                $this->headers($key, $userAgent),
                $body,
                self::CONNECT_TIMEOUT,
                $timeout > 0 ? $timeout : 10,
            );
        } catch (Throwable $failure) {
            return self::errorResult($failure->getMessage());
        }

        if ($response->status === 0) {
            return self::errorResult($response->error ?? 'Network error');
        }

        return self::normalise($response);
    }

    /**
     * The five headers every request carries. The set is exact: the server
     * authenticates on `Authorization`, versions on `Ranetrace-API-Version` and
     * attributes the SDK and feature on `User-Agent`.
     *
     * @return array<string, string>
     */
    private function headers(string $key, string $userAgent): array
    {
        return [
            'Authorization' => 'Bearer '.$key,
            'User-Agent' => $userAgent,
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
            'Ranetrace-API-Version' => self::API_VERSION,
        ];
    }

    private function url(string $path): string
    {
        return $this->config->baseUrl().'/'.mb_ltrim($path, '/');
    }
}
