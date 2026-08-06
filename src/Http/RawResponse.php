<?php

declare(strict_types=1);

namespace Ranetrace\Php\Http;

/**
 * An HTTP response as the transport saw it: status, raw body, headers.
 *
 * Deliberately dumb. Interpreting the body, deciding what counts as success and
 * mapping a status onto a buffering decision all belong to `ApiClient` and
 * `Worker\Worker`; keeping that out of here is what lets a host swap the
 * transport without inheriting any policy.
 *
 * `error` carries a transport-level failure message (DNS, TLS, timeout, refused
 * connection) alongside status 0. It is a fourth, optional property rather than
 * a separate exception type because the whole contract of this layer is that it
 * does not throw.
 */
final readonly class RawResponse
{
    /**
     * @param  int  $status  HTTP status code, or 0 when the request never completed.
     * @param  array<string, string>  $headers  Response headers with lowercased names.
     */
    public function __construct(
        public int $status,
        public string $body,
        public array $headers = [],
        public ?string $error = null,
    ) {}

    /**
     * A transport-level failure, with no HTTP response to speak of.
     */
    public static function transportFailure(string $error): self
    {
        return new self(0, '', [], $error);
    }

    public function header(string $name): ?string
    {
        return $this->headers[mb_strtolower($name)] ?? null;
    }
}
