<?php

declare(strict_types=1);

namespace Ranetrace\Php\Errors;

/**
 * The lines around one line of one file, as {@see SourceReader} cut them:
 * scrubbed, capped and dedented together.
 *
 * @internal
 */
final readonly class SourceWindow
{
    /**
     * @param  int  $startLine  The 1-based file line of `$lines[0]`.
     * @param  list<string>  $lines  One entry per file line, no trailing newline.
     * @param  string  $context  The same lines as the item's `context` string has always carried them, joined by newlines and ending in one when the last line did.
     */
    public function __construct(
        public int $startLine,
        public array $lines,
        public string $context,
    ) {}

    /**
     * The 1-based position of $line within the window, which is what the
     * item's `highlight_line` holds.
     */
    public function highlightLine(int $line): int
    {
        return $line - $this->startLine + 1;
    }

    /**
     * The wire `source` object, or null when the window does not hold $line
     * (a line past the end of the file, or line 0).
     *
     * @return array{start_line: int, lines: list<string>}|null
     */
    public function sourceObject(int $line): ?array
    {
        if ($this->lines === [] || $line < $this->startLine || $line >= $this->startLine + count($this->lines)) {
            return null;
        }

        return ['start_line' => $this->startLine, 'lines' => $this->lines];
    }
}
