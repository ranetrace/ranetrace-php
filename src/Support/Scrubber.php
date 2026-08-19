<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * Redaction, as the shared payload builders need it.
 *
 * {@see SecretScrubber} is this package's implementation. The interface exists
 * because the Laravel SDK still owns a scrubber of its own: it resolves the
 * secret-bearing segments of a URL from the router, per URL, which a
 * framework-agnostic scrubber cannot do. Until the two are merged (slice C of
 * the shared-core migration), the shared builders take whichever scrubber their
 * host brought and the redaction semantics stay exactly what that host already
 * shipped.
 *
 * `$sensitiveValues` is the caller's answer to "which path segments hold a
 * secret", since a path segment carries no marker saying so. Null means
 * query-only scrubbing, which is the correct behaviour for a host that cannot
 * say.
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
     * @param  array<int, string>|null  $sensitiveValues
     */
    public function scrubUrlPath(?string $url, ?array $sensitiveValues = null): ?string;

    /**
     * Key-based redaction plus redaction of secrets inside URL-shaped string
     * values, for free-form, untrusted data.
     *
     * @param  array<int, string>|null  $sensitiveValues
     */
    public function scrubDeep(mixed $data, ?array $sensitiveValues = null): mixed;
}
