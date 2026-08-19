<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * Redaction, as the shared payload builders need it.
 *
 * {@see SecretScrubber} is the implementation both SDKs use. The interface
 * stays because the builders should depend on the capability rather than the
 * class, and because a host with an unusual redaction obligation of its own can
 * satisfy it, but there is no second implementation to keep in step any more:
 * `ranetrace/ranetrace-laravel` deleted its copy and its `CoreScrubber` bridge
 * when the two merged.
 *
 * `$sensitiveValues` is the caller's answer to "which path segments hold a
 * secret", since a path segment carries no marker saying so. Null means
 * query-only scrubbing, a list names the secret segment values, and a callable
 * is asked per URL, which is what a host with a router needs for free-form data
 * holding URLs from requests other than the current one.
 */
interface Scrubber
{
    /**
     * Redact `key=value` pairs in a free-form string when the key contains a
     * sensitive fragment.
     */
    public function scrubString(string $value): string;

    /**
     * Redact the sensitive query (and query-shaped fragment) parameters of a
     * URL, leaving every other byte of it intact.
     */
    public function scrubUrl(?string $url): ?string;

    /**
     * Redact the path segments whose value is one of $sensitiveValues.
     *
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitiveValues
     */
    public function scrubUrlPath(?string $url, array|callable|null $sensitiveValues = null): ?string;

    /**
     * Key-based redaction plus redaction of secrets inside URL-shaped string
     * values, for free-form, untrusted data.
     *
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitiveValues
     */
    public function scrubDeep(mixed $data, array|callable|null $sensitiveValues = null): mixed;
}
