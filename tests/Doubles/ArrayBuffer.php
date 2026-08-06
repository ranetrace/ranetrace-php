<?php

declare(strict_types=1);

namespace Ranetrace\Php\Tests\Doubles;

use Ranetrace\Php\Buffer\BufferInterface;

/**
 * In-memory buffer for feature tests: same contract as the file buffer, none
 * of the filesystem. Tests assert on $items directly.
 */
class ArrayBuffer implements BufferInterface
{
    /** @var array<string, array<int, array{id: string, data: array<string, mixed>, timestamp: int}>> */
    public array $items = [];

    public bool $rejectWrites = false;

    public function addItem(string $type, array $data): bool
    {
        return $this->addItems($type, [$data]);
    }

    public function addItems(string $type, array $items): bool
    {
        if ($this->rejectWrites) {
            return false;
        }

        foreach ($items as $data) {
            $this->items[$type][] = [
                'id' => bin2hex(random_bytes(8)),
                'data' => $data,
                'timestamp' => time(),
            ];
        }

        return true;
    }

    public function take(string $type, int $limit): array
    {
        $taken = array_slice($this->items[$type] ?? [], 0, $limit);
        $this->items[$type] = array_slice($this->items[$type] ?? [], $limit);

        return $taken;
    }

    public function count(string $type): int
    {
        return count($this->items[$type] ?? []);
    }

    public function types(): array
    {
        return ['errors', 'events', 'logs', 'javascript_errors'];
    }

    /**
     * The raw payloads buffered for a type, unwrapped from their envelopes.
     *
     * @return array<int, array<string, mixed>>
     */
    public function payloads(string $type): array
    {
        return array_column($this->items[$type] ?? [], 'data');
    }
}
