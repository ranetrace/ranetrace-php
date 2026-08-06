<?php

declare(strict_types=1);

namespace Ranetrace\Php\JavaScript;

/**
 * What {@see Relay::handleRequest()} decided: an HTTP status and a JSON body.
 *
 * Deliberately not an HTTP response object. The relay has to work whether the
 * host is PSR-7, a framework's own response class, or plain `echo`, so it
 * returns the decision and lets the host build the response. {@see Relay::handle()}
 * is the built-in "plain echo" adapter.
 */
final class RelayResponse
{
    /**
     * @param  array<string, mixed>  $body
     */
    public function __construct(
        public int $status,
        public array $body,
    ) {}

    /**
     * The body encoded for transmission. Slashes stay escaped so the payload is
     * safe to inline anywhere, and encoding never fails hard: this sits on a
     * capture path.
     */
    public function toJson(): string
    {
        return (string) json_encode($this->body, JSON_PARTIAL_OUTPUT_ON_ERROR);
    }
}
