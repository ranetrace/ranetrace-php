<?php

declare(strict_types=1);

namespace Ranetrace\Php\Logging;

use Ranetrace\Php\Config;
use Ranetrace\Php\Support\DataSanitizer;
use Ranetrace\Php\Support\PayloadSizer;
use Ranetrace\Php\Support\Scrubber;

/**
 * Shapes one log record into the six-key log item the Ranetrace API accepts.
 *
 * Shared with `ranetrace/ranetrace-laravel`, which shapes its records here too:
 * the caps, the `_truncated` marker wording and the environment vocabulary
 * attached to `extra` are the wire contract and must not drift between the two.
 *
 * Per-field caps bound the size of a SINGLE captured item. They do not by
 * themselves keep a 1000-item batch under the API's 5MB request limit; that is
 * the transport's pre-flight byte-budget trim. NOT user-tunable: raising any of
 * them widens per-item size and the 413 risk.
 */
final class LogItemBuilder
{
    private const string TRUNCATION_SUFFIX = '... (truncated)';

    private const int MAX_MESSAGE_LENGTH = 50_000;

    private const int MAX_CONTEXT_BYTES = 51_200;

    private const int MAX_EXTRA_BYTES = 10_240;

    public function __construct(
        private readonly Config $config,
        private readonly Scrubber $scrubber,
    ) {}

    /**
     * @param  array<array-key, mixed>  $context  The record's own context, free-shape and untrusted.
     * @param  array<array-key, mixed>  $extra  The record's own extra, free-shape and untrusted.
     * @param  string  $timestamp  ISO 8601, from the record's own clock.
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitivePathValues  Path segment values to redact from any URL hiding in $context or $extra: a fixed list, or a per-URL resolver for a host with a router. Null means query-only scrubbing.
     * @return array{
     *     level: string,
     *     message: string,
     *     context: array<array-key, mixed>,
     *     channel: string,
     *     timestamp: string,
     *     extra: array<string, mixed>,
     * }
     */
    public function build(
        string $level,
        string $message,
        array $context,
        string $channel,
        string $timestamp,
        array $extra,
        array|callable|null $sensitivePathValues = null,
    ): array {
        return [
            'level' => mb_strtolower($level),
            'message' => $this->message($message),
            // Sanitize for serialization, redact secrets (by sensitive key name,
            // plus tokens inside URL-shaped string values), then cap size,
            // replacing mid-structure rather than truncating, since partial JSON
            // is not JSON.
            'context' => PayloadSizer::capBytes(
                (array) $this->scrubber->scrubDeep(DataSanitizer::sanitizeForSerialization($context), $sensitivePathValues),
                self::MAX_CONTEXT_BYTES,
                'Context exceeded 50KB limit and was removed',
            ),
            'channel' => $channel,
            'timestamp' => $timestamp,
            'extra' => $this->extra($extra, $sensitivePathValues),
        ];
    }

    /**
     * Scrub key=value secrets BEFORE truncating, so a secret cannot survive by
     * being split across the length boundary.
     */
    private function message(string $message): string
    {
        $message = $this->scrubber->scrubString($message);

        if (mb_strlen($message) <= self::MAX_MESSAGE_LENGTH) {
            return $message;
        }

        return mb_substr($message, 0, self::MAX_MESSAGE_LENGTH - mb_strlen(self::TRUNCATION_SUFFIX)).self::TRUNCATION_SUFFIX;
    }

    /**
     * The record's own extra, capped, plus the environment vocabulary.
     *
     * Only the user-supplied part is capped, and the vocabulary is attached
     * afterwards, so the triage metadata survives even when the user extra is
     * dropped wholesale for being oversized. `framework` and `framework_version`
     * appear only when the host configured them: `extra` is not
     * strict-field-validated, so an absent key costs nothing, while a null one
     * would read as "no framework" rather than "not said".
     *
     * @param  array<array-key, mixed>  $extra
     * @param  array<int, string>|(callable(string): (array<int, string>|null))|null  $sensitivePathValues
     * @return array<string, mixed>
     */
    private function extra(array $extra, array|callable|null $sensitivePathValues): array
    {
        $capped = PayloadSizer::capBytes(
            (array) $this->scrubber->scrubDeep(DataSanitizer::sanitizeForSerialization($extra), $sensitivePathValues),
            self::MAX_EXTRA_BYTES,
            'Extra data exceeded 10KB limit and was removed',
        );

        $environment = $this->config->get('environment');

        $vocabulary = [
            'environment' => is_scalar($environment) ? (string) $environment : '',
            'php_version' => (string) phpversion(),
        ];

        foreach (['framework', 'framework_version'] as $key) {
            $value = $this->config->get($key);

            if (is_string($value) && $value !== '') {
                $vocabulary[$key] = $value;
            }
        }

        return array_merge($capped, $vocabulary);
    }
}
