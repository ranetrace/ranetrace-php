<?php

declare(strict_types=1);

namespace Ranetrace\Php\Http;

use InvalidArgumentException;

/**
 * The one place either SDK looks up where a batch goes.
 *
 * {@see contract()} is the four types the wire contract names
 * (`contract/endpoints.json`). A host with a capture type of its own extends the
 * table with {@see with()} rather than keeping a second, drifting copy of the
 * four: the Laravel SDK adds `page_visits`, which is a Laravel-only feature and
 * therefore not part of the shared contract.
 */
final class EndpointTable
{
    /**
     * The `{version}` segment of the User-Agent. Its own version, deliberately
     * independent of the package version: it changes when the attribution
     * format changes, not when the SDK ships.
     */
    public const string USER_AGENT_VERSION = '1.0';

    /**
     * @param  array<string, Endpoint>  $endpoints  Keyed by capture type.
     */
    private function __construct(private readonly array $endpoints) {}

    /**
     * The four types `contract/endpoints.json` names, in contract order.
     */
    public static function contract(): self
    {
        return new self([
            'errors' => new Endpoint('errors', '/errors/store', 'errors', 'Errors', 'errors.timeout'),
            'events' => new Endpoint('events', '/events/store', 'events', 'Events', 'events.timeout'),
            'logs' => new Endpoint('logs', '/logs/store', 'logs', 'Logs', 'logging.timeout'),
            'javascript_errors' => new Endpoint('javascript_errors', '/javascript-errors/store', 'javascript_errors', 'JavaScriptErrors', 'javascript_errors.timeout'),
        ]);
    }

    /**
     * A copy of this table with additional types appended. An entry for a type
     * the table already holds replaces it.
     */
    public function with(Endpoint ...$endpoints): self
    {
        $merged = $this->endpoints;

        foreach ($endpoints as $endpoint) {
            $merged[$endpoint->type] = $endpoint;
        }

        return new self($merged);
    }

    public function has(string $type): bool
    {
        return isset($this->endpoints[$type]);
    }

    public function find(string $type): ?Endpoint
    {
        return $this->endpoints[$type] ?? null;
    }

    /**
     * @throws InvalidArgumentException When the type is not in the table. The
     *                                  caller asked to send something nothing knows how to address, which is a
     *                                  programming error rather than a capture failure.
     */
    public function get(string $type): Endpoint
    {
        return $this->endpoints[$type] ?? throw new InvalidArgumentException("Unknown batch type: {$type}");
    }

    /**
     * @return list<string>
     */
    public function types(): array
    {
        return array_keys($this->endpoints);
    }

    /**
     * @return array<string, Endpoint>
     */
    public function all(): array
    {
        return $this->endpoints;
    }
}
