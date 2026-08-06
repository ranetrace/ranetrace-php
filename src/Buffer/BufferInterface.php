<?php

declare(strict_types=1);

namespace Ranetrace\Php\Buffer;

/**
 * The per-type FIFO buffer capture writes into and the worker drains.
 *
 * Feature code (errors, logs, events, JavaScript relay) type-hints this
 * interface rather than the file implementation so it can be tested against an
 * in-memory double, and so a host with a better store can swap one in without
 * touching the capture path.
 */
interface BufferInterface
{
    /**
     * Append one payload. Returns false when the item could not be buffered
     * (lock contention, unwritable path); capture code treats that as a silent
     * drop after internal logging, never as an exception.
     *
     * @param  array<string, mixed>  $data
     */
    public function addItem(string $type, array $data): bool;

    /**
     * Append many payloads in arrival order under a single lock.
     *
     * @param  array<int, array<string, mixed>>  $items
     */
    public function addItems(string $type, array $items): bool;

    /**
     * Atomically remove and return up to $limit envelopes from the head.
     *
     * Envelope shape: ['id' => string, 'data' => array, 'timestamp' => int].
     * Items leave the buffer before any send is attempted; failed sends
     * re-buffer via addItems(), which is what makes delivery at-least-once.
     *
     * @return array<int, array{id: string, data: array<string, mixed>, timestamp: int}>
     */
    public function take(string $type, int $limit): array;

    public function count(string $type): int;

    /**
     * The buffer types this SDK captures.
     *
     * @return list<string>
     */
    public function types(): array;
}
