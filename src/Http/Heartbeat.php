<?php

declare(strict_types=1);

namespace Ranetrace\Php\Http;

use Composer\InstalledVersions;
use Ranetrace\Php\Support\StringLimit;
use Throwable;

/**
 * One heartbeat: the request that tells Ranetrace an SDK's worker ran, whether
 * or not it had anything to send.
 *
 * An SDK sends nothing while its buffer is empty, so without this the API
 * cannot tell a quiet application from one whose worker stopped. The request
 * is described in `contract/heartbeat.json`, and everything about it that both
 * SDKs must agree on lives here: the path, the body, the User-Agent and how
 * often one goes out. `ranetrace/ranetrace-laravel` builds its own heartbeat
 * from this class with its own SDK name and package, as it reads
 * {@see EndpointTable} for its batches.
 *
 * It is not an {@see Endpoint}: a heartbeat has no items, no wrapper key and no
 * buffer type, and an entry in the endpoint table would make the worker try to
 * drain one.
 */
final readonly class Heartbeat
{
    public const string PATH = '/heartbeat';

    /**
     * The `{Feature}` segment of the User-Agent.
     */
    public const string FEATURE = 'Heartbeat';

    /**
     * The least time between two heartbeats of one application. The API calls
     * an application stopped after a silence several times this long, so one
     * heartbeat that fails is not a reason to send the next one sooner.
     */
    public const int INTERVAL_SECONDS = 300;

    /**
     * Total request timeout. Fixed, because a heartbeat belongs to no feature
     * and so to no feature's timeout setting.
     */
    public const int TIMEOUT_SECONDS = 10;

    /**
     * The API refuses a longer `sdk_version`, so a longer one is cut.
     */
    public const int MAX_VERSION_LENGTH = 50;

    /**
     * Sent when the version cannot be found. The API requires the field, and a
     * worker that ran should still be heard.
     */
    public const string UNKNOWN_VERSION = 'unknown';

    /**
     * @param  string  $sdk  The `{SDK}` segment of the User-Agent, e.g. `PHP` or `Laravel`. The body carries it in lower case.
     * @param  string  $version  The SDK package's version.
     */
    public function __construct(
        public string $sdk,
        public string $version,
    ) {}

    /**
     * The heartbeat of an installed Composer package, with the version
     * Composer installed it at, as Composer spells it: `v1.7.0` for a tag,
     * `dev-main` for a branch.
     *
     * @param  string  $sdk  The `{SDK}` segment of the User-Agent.
     * @param  string  $package  The Composer name, e.g. `ranetrace/ranetrace-php`.
     */
    public static function forPackage(string $sdk, string $package): self
    {
        try {
            $version = class_exists(InstalledVersions::class) ? InstalledVersions::getPrettyVersion($package) : null;
        } catch (Throwable) {
            // Composer throws for a package it did not install. The worker
            // still ran, so the heartbeat goes out without a version.
            $version = null;
        }

        return new self($sdk, $version ?? self::UNKNOWN_VERSION);
    }

    /**
     * Whether the API took the heartbeat: any 2xx, as `contract/heartbeat.json`
     * says, whatever the body. `success` is not read, because it also asks for
     * a JSON body.
     *
     * Takes the normalised result of either SDK's client: this package's, or
     * the Laravel client's, whose `headers` may be empty and which has no
     * `error` key on success. A status that is not an integer reads as 0, a
     * request that reached no status.
     *
     * @param  array{status?: int, data?: array<string, mixed>, headers?: array<string, mixed>, error?: ?string}  $result
     */
    public static function accepted(array $result): bool
    {
        $status = self::statusOf($result);

        return $status >= 200 && $status < 300;
    }

    /**
     * The release check's line for the API's answer to a heartbeat:
     * `accepted`, `failed` when no status came back, or `refused` with the
     * status and the API's message. Takes the same results as
     * {@see accepted()}.
     *
     * @param  array{status?: int, data?: array<string, mixed>, headers?: array<string, mixed>, error?: ?string}  $result
     * @param  string  $baseUrl  The API the heartbeat was sent to, named when it could not be reached.
     */
    public static function answerLine(array $result, string $baseUrl): string
    {
        if (self::accepted($result)) {
            return 'accepted';
        }

        $status = self::statusOf($result);

        if ($status === 0) {
            return "failed: could not reach {$baseUrl} (".($result['error'] ?? 'unknown network error').')';
        }

        $body = is_array($result['data'] ?? null) ? $result['data'] : [];

        return "refused: the API answered {$status} (".ResponsePolicy::errorMessage($body, 'no message').')';
    }

    /**
     * The request body. The API matches it strictly: exactly these two keys.
     *
     * @return array{sdk: string, sdk_version: string}
     */
    public function body(): array
    {
        $version = mb_trim($this->version);

        return [
            'sdk' => mb_strtolower($this->sdk),
            'sdk_version' => $version === '' ? self::UNKNOWN_VERSION : StringLimit::cut($version, self::MAX_VERSION_LENGTH),
        ];
    }

    /**
     * The User-Agent in the format every request carries, e.g.
     * `Ranetrace-PHP/Heartbeat/1.0`.
     */
    public function userAgent(): string
    {
        return EndpointTable::userAgent($this->sdk, self::FEATURE);
    }

    /**
     * @param  array{status?: int, data?: array<string, mixed>, headers?: array<string, mixed>, error?: ?string}  $result
     */
    private static function statusOf(array $result): int
    {
        $status = $result['status'] ?? null;

        return is_int($status) ? $status : 0;
    }
}
