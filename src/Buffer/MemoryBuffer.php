<?php

declare(strict_types=1);

namespace Ranetrace\Php\Buffer;

/**
 * A buffer that lives in this object only and is gone with it.
 *
 * For capture that must not reach the spool: `Worker\TestRun` builds its test
 * items through the real capture path into one of these, so they pass the same
 * gating, shaping, scrubbing and byte budget as any item, and then takes them
 * out to send them itself. Nothing here is shared between processes, so it is
 * never a substitute for {@see FileBuffer}.
 */
final class MemoryBuffer implements BufferInterface
{
    /**
     * The same types the file buffer spools.
     *
     * @var list<string>
     */
    private const array TYPES = ['errors', 'events', 'logs', 'javascript_errors'];

    /**
     * @var array<string, list<array{id: string, data: array<string, mixed>, timestamp: int}>>
     */
    private array $items = [];

    public function addItem(string $type, array $data): bool
    {
        return $this->addItems($type, [$data]);
    }

    public function addItems(string $type, array $items): bool
    {
        if (! in_array($type, self::TYPES, true)) {
            return false;
        }

        foreach ($items as $data) {
            $this->items[$type][] = [
                'id' => bin2hex(random_bytes(16)),
                'data' => $data,
                'timestamp' => time(),
            ];
        }

        return true;
    }

    public function take(string $type, int $limit): array
    {
        if ($limit < 1) {
            return [];
        }

        $buffer = $this->items[$type] ?? [];

        $this->items[$type] = array_slice($buffer, $limit);

        return array_slice($buffer, 0, $limit);
    }

    public function returnItems(string $type, array $envelopes): void
    {
        if (! in_array($type, self::TYPES, true) || $envelopes === []) {
            return;
        }

        $this->items[$type] = [...array_values($envelopes), ...$this->items[$type] ?? []];
    }

    public function count(string $type): int
    {
        return count($this->items[$type] ?? []);
    }

    public function types(): array
    {
        return self::TYPES;
    }
}
