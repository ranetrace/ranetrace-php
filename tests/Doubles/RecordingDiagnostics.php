<?php

declare(strict_types=1);

namespace Ranetrace\Php\Tests\Doubles;

use Ranetrace\Php\Support\Diagnostics;
use RuntimeException;

/**
 * A diagnostics sink that keeps every entry in memory, so a test can assert
 * on the exact lines a shared class writes. With `$throws` set, every write
 * throws instead, for the tests that prove a failing sink costs nothing.
 */
final class RecordingDiagnostics implements Diagnostics
{
    /** @var list<array{level: string, message: string, context: array<string, mixed>}> */
    public array $records = [];

    public function __construct(private readonly bool $throws = false) {}

    public function debug(string $message, array $context = []): void
    {
        $this->record('debug', $message, $context);
    }

    public function info(string $message, array $context = []): void
    {
        $this->record('info', $message, $context);
    }

    public function notice(string $message, array $context = []): void
    {
        $this->record('notice', $message, $context);
    }

    public function warning(string $message, array $context = []): void
    {
        $this->record('warning', $message, $context);
    }

    public function error(string $message, array $context = []): void
    {
        $this->record('error', $message, $context);
    }

    public function critical(string $message, array $context = []): void
    {
        $this->record('critical', $message, $context);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function record(string $level, string $message, array $context): void
    {
        if ($this->throws) {
            throw new RuntimeException('The diagnostics sink is unavailable');
        }

        $this->records[] = ['level' => $level, 'message' => $message, 'context' => $context];
    }
}
