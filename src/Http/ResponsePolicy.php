<?php

declare(strict_types=1);

namespace Ranetrace\Php\Http;

/**
 * The client's response matrix, in one place for both SDKs.
 *
 * This is contract, not implementation detail: which statuses re-buffer, which
 * drop and which pause globally are all things the server relies on the client
 * doing. `contract/responses.json` is the written form and
 * `tests/Contract` asserts this class against it.
 *
 * What is NOT decided here is how a host acts on the decision. The file-based
 * worker in this package has no queue to release to, so a transient failure
 * pauses on the spot and the next run is the retry; the Laravel SDK's queued job
 * spends its 60/300/900s retry envelope first and pauses only once that is
 * exhausted. {@see BatchOutcome::$transient} is the seam between the two, and
 * both land on the same pause, which is the part the contract fixes.
 */
final class ResponsePolicy
{
    /**
     * The standard back-off. Long enough that a degraded endpoint gets real
     * relief, short enough that a recovered one is retried within the buffer's
     * idle TTL.
     */
    public const int PAUSE_SECONDS = 900;

    /**
     * Substitute for an absent or non-positive `Retry-After`. A missing header
     * is stored as `''`, and `(int) '' === 0`; without this a rate-limited
     * client would take a zero-second pause and keep hammering the endpoint on
     * every run. It is a substitute, not a lower bound: `Retry-After: 5` really
     * pauses five seconds.
     */
    public const int RATE_LIMIT_FLOOR_SECONDS = 60;

    /**
     * The message a failed response carries, for the host's diagnostics log
     * only. The matrix above keys off the status, never off this.
     *
     * @param  array<string, mixed>  $body  The decoded response body.
     */
    public static function errorMessage(array $body, string $fallback): string
    {
        $error = $body['error'] ?? null;
        $message = is_array($error) ? ($error['message'] ?? null) : null;

        return is_string($message) && $message !== '' ? $message : $fallback;
    }

    /**
     * Read one normalised API result.
     *
     * @param  array{status?: int, data?: array<string, mixed>, headers?: array<string, mixed>, error?: ?string}  $result
     */
    public function decide(array $result): BatchOutcome
    {
        $status = is_int($result['status'] ?? null) ? $result['status'] : 0;
        $body = is_array($result['data'] ?? null) ? $result['data'] : [];

        // Status 0 is a transport failure the API client already caught, so the
        // raw cURL message never escapes into the host application.
        if ($status === 0) {
            return $this->transient(0, 'network');
        }

        return match ($status) {
            200 => $this->success($body),
            401 => new BatchOutcome(401, true, false, PauseScope::Everything, self::PAUSE_SECONDS, '401', false),
            403 => new BatchOutcome(403, true, false, PauseScope::Feature, self::PAUSE_SECONDS, '403', false),
            413 => new BatchOutcome(413, false, true, PauseScope::Feature, self::PAUSE_SECONDS, '413', false),
            422 => new BatchOutcome(422, false, true, PauseScope::Feature, self::PAUSE_SECONDS, '422', false),
            429 => $this->rateLimited($result['headers'] ?? []),
            default => $this->transient($status, (string) $status),
        };
    }

    /**
     * Validation passed for the whole batch and processing ran per item. Items
     * named by `unprocessed_indexes` come back; items counted as failed are
     * terminal, because the server rejected them individually and would reject
     * them again.
     *
     * @param  array<string, mixed>  $body
     */
    private function success(array $body): BatchOutcome
    {
        $counters = BatchCounters::fromResponseBody($body);

        $indexes = [];

        if ($counters->hasUnprocessed()) {
            $reported = is_array($body['unprocessed_indexes'] ?? null) ? $body['unprocessed_indexes'] : [];

            foreach ($reported as $index) {
                if (is_int($index)) {
                    $indexes[] = $index;
                }
            }
        }

        return new BatchOutcome(
            status: 200,
            rebuffer: false,
            drop: false,
            pauseScope: PauseScope::None,
            pauseSeconds: null,
            reason: '200',
            transient: false,
            stampLastBatch: true,
            counters: $counters,
            unprocessedIndexes: $indexes,
        );
    }

    /**
     * @param  array<string, mixed>  $headers
     */
    private function rateLimited(array $headers): BatchOutcome
    {
        $retryAfter = $headers['retry-after'] ?? 0;
        $retryAfter = is_scalar($retryAfter) ? (int) $retryAfter : 0;

        if ($retryAfter < 1) {
            $retryAfter = self::RATE_LIMIT_FLOOR_SECONDS;
        }

        return new BatchOutcome(429, true, false, PauseScope::Feature, $retryAfter, '429', false);
    }

    /**
     * A 500, a network failure, or any status this matrix does not name. All
     * treated the same: re-buffer, back off, and let the next attempt be the
     * retry.
     */
    private function transient(int $status, string $reason): BatchOutcome
    {
        return new BatchOutcome($status, true, false, PauseScope::Feature, self::PAUSE_SECONDS, $reason, true);
    }
}
