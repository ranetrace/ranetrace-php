<?php

declare(strict_types=1);

use Ranetrace\Php\Worker\TestOutcome;
use Ranetrace\Php\Worker\TestResult;

/**
 * The wording of every outcome, the pauses a 200 lifts and the closing
 * sentence are pinned through `vendor/bin/ranetrace-test`'s output in
 * SendTestTest. What is left here is what that test cannot reach: a result in
 * the shape the Laravel client returns, which this package's client never
 * produces, and the rules as the other SDK calls them.
 */
it('reads a result in the laravel client\'s shape, with empty headers and no error key', function (array $result, TestOutcome $outcome, int $status, string $message, int $seconds): void {
    $tested = TestResult::fromResponse($result);

    expect($tested->outcome)->toBe($outcome)
        ->and($tested->status)->toBe($status)
        ->and($tested->message)->toBe($message)
        ->and($tested->seconds)->toBe($seconds);
})->with([
    'a 200 that processed the item' => [
        ['status' => 200, 'success' => true, 'data' => ['success' => true, 'items' => ['received' => 1, 'processed' => 1]], 'headers' => []],
        TestOutcome::Accepted, 200, '', 0,
    ],
    'a 200 that ignored the item' => [
        ['status' => 200, 'success' => true, 'data' => ['items' => ['received' => 1, 'processed' => 0, 'ignored' => 1]], 'headers' => []],
        TestOutcome::AcceptedNotStored, 200, '', 0,
    ],
    'a 200 with an empty body' => [
        ['status' => 200, 'success' => false, 'data' => [], 'headers' => []],
        TestOutcome::Unrecognised, 200, '', 0,
    ],
    'a 429 without a Retry-After header' => [
        ['status' => 429, 'success' => false, 'data' => [], 'headers' => []],
        TestOutcome::RateLimited, 429, '', 60,
    ],
    'a 429 with one' => [
        ['status' => 429, 'success' => false, 'data' => [], 'headers' => ['retry-after' => '30']],
        TestOutcome::RateLimited, 429, '', 30,
    ],
    'a 401 without a message' => [
        ['status' => 401, 'success' => false, 'data' => [], 'headers' => []],
        TestOutcome::Unauthorized, 401, 'Unauthorized', 0,
    ],
    'a 403 with a message' => [
        ['status' => 403, 'success' => false, 'data' => ['error' => ['message' => 'Feature disabled']], 'headers' => []],
        TestOutcome::Forbidden, 403, 'Feature disabled', 0,
    ],
    'a 503' => [
        ['status' => 503, 'success' => false, 'data' => [], 'headers' => []],
        TestOutcome::Failed, 503, 'no message', 0,
    ],
    'no status and no error' => [
        ['status' => 0, 'success' => false, 'data' => [], 'headers' => []],
        TestOutcome::Unreachable, 0, 'unknown network error', 0,
    ],
    'no status with an error' => [
        ['status' => 0, 'success' => false, 'data' => [], 'headers' => [], 'error' => 'Connection refused'],
        TestOutcome::Unreachable, 0, 'Connection refused', 0,
    ],
]);

it('says an answer that reached no status and named no error could not reach the api', function (): void {
    expect(TestResult::fromResponse(['status' => 0, 'data' => [], 'headers' => []])->line('events', 'https://api.example.test/v1', false))
        ->toBe('failed: could not reach https://api.example.test/v1 (unknown network error)');
});

it('lifts a feature pause after a 200 unless it answered one batch or a rate limit', function (string $reason, bool $lifts): void {
    expect(TestResult::liftsFeaturePause($reason))->toBe($lifts);
})->with([
    'a 429' => ['429', false],
    'a 413' => ['413', false],
    'a 422' => ['422', false],
    'a network failure' => ['network', true],
    'a 403' => ['403', true],
    'a 500' => ['500', true],
    'a 401' => ['401', true],
]);

it('disproves the pauses only with a 200 that came from the ranetrace api', function (TestResult $result, bool $disproves): void {
    expect($result->disprovesPauses())->toBe($disproves);
})->with([
    'an accepted item' => [fn (): TestResult => TestResult::fromResponse(['status' => 200, 'data' => ['items' => ['received' => 1, 'processed' => 1]]]), true],
    'a refused item' => [fn (): TestResult => TestResult::fromResponse(['status' => 200, 'data' => ['items' => ['received' => 1, 'processed' => 0, 'failed' => 1]]]), true],
    'an unprocessed item' => [fn (): TestResult => TestResult::fromResponse(['status' => 200, 'data' => ['items' => ['received' => 1, 'processed' => 0, 'unprocessed' => 1]]]), true],
    'a 200 that counts nothing' => [fn (): TestResult => TestResult::fromResponse(['status' => 200, 'data' => []]), false],
    'a 500' => [fn (): TestResult => TestResult::fromResponse(['status' => 500, 'data' => []]), false],
    'no status' => [fn (): TestResult => TestResult::fromResponse(['status' => 0]), false],
    'a skipped type' => [fn (): TestResult => TestResult::skipped(), false],
    'a type not sent' => [fn (): TestResult => TestResult::notSent(), false],
    'a type not captured' => [fn (): TestResult => TestResult::notCaptured(''), false],
]);
