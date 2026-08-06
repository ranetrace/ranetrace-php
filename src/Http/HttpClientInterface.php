<?php

declare(strict_types=1);

namespace Ranetrace\Php\Http;

/**
 * The one call the SDK makes over the network.
 *
 * The interface exists so the transport is a seam: the package suite asserts the
 * exact wire shape against a fake, and a host that already owns a configured
 * HTTP stack (a proxy, a mutual-TLS client, an in-process test transport) can
 * hand one in instead of the bundled cURL implementation.
 *
 * Implementations must never throw. A transport failure is reported as a
 * `RawResponse` with status 0 and a human-readable `error`, because a monitoring
 * SDK that breaks the host application while failing to report a problem is
 * worse than one that stays quiet.
 */
interface HttpClientInterface
{
    /**
     * @param  array<string, string>  $headers  Header name => value.
     * @param  int  $connectTimeout  Seconds to wait for the connection to be established.
     * @param  int  $timeout  Seconds to wait for the whole request.
     */
    public function post(string $url, array $headers, string $body, int $connectTimeout, int $timeout): RawResponse;
}
