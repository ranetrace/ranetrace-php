<?php

declare(strict_types=1);

namespace Ranetrace\Php\Errors;

use Ranetrace\Php\Support\Diagnostics;
use Ranetrace\Php\Support\Scrubber;
use Ranetrace\Php\Support\Utf8;
use Throwable;
use UnexpectedValueException;

/**
 * Reads the source lines an error item carries: the item's own `context`, each
 * app frame's `source` and each previous exception's throw site, all cut by
 * the same rules.
 *
 * One reader serves one item. Every location is announced with {@see want()}
 * first, and the first {@see window()} call for a file reads it once and cuts
 * every window wanted from it, so a file that ten frames share is read once and
 * no file is held in memory past that call. A window asked for that was never
 * announced is still served, by reading its file again.
 *
 * Only regular, readable files under {@see MAX_SOURCE_FILE_BYTES} are read: a
 * generated or concatenated multi-megabyte file would be read whole for eleven
 * lines. Code run through `eval()` has no file to read, and a stream wrapper
 * path other than `phar://` is never opened, since a wrapper is host code that
 * could do anything when it is touched. A filesystem call that fails is
 * silenced and costs that one window: a host error handler that turns warnings
 * into exceptions must not see the SDK's file checks. A scrubber that throws
 * costs that one window too.
 *
 * Every line is repaired to valid UTF-8, then the window is scrubbed for
 * secrets as a whole together with the lines above it (see
 * {@see LOOKBEHIND_LINES}), so one that spans lines is caught, and only then
 * is each line capped, so a secret cannot survive by straddling the cap.
 *
 * @internal
 */
final class SourceReader
{
    public const int MAX_SOURCE_FILE_BYTES = 1_048_576;

    /**
     * A line is capped at 2,000 characters, and the suffix is added OUTSIDE
     * the cap, so a line is at most 2,015 characters: what both SDKs have
     * always sent in `context`, and the bound the wire contract states.
     */
    public const int MAX_LINE_LENGTH = 2_000;

    /**
     * The window is the line plus five lines either side, clamped at the start
     * and the end of the file.
     */
    public const int WINDOW_LINES = 11;

    private const int LINES_BEFORE = 5;

    /**
     * The lines above a window that are scrubbed with it and then dropped, so
     * a key, heredoc opener or call bracket that opens above the window's first
     * line still has its value redacted inside the window. A construct opened
     * further up is not caught, except a private key body, which the scrubber
     * recognises line by line. It is bounded because every window of every
     * error pays for it, and no realistic secret spans further.
     */
    private const int LOOKBEHIND_LINES = 50;

    private const string TRUNCATION_SUFFIX = '... (truncated)';

    /**
     * @var array<string, array<int, true>>
     */
    private array $wanted = [];

    /**
     * Cut windows per file and line; a null window is a file that could not be
     * read.
     *
     * @var array<string, array<int, SourceWindow|null>>
     */
    private array $windows = [];

    public function __construct(
        private readonly Scrubber $scrubber,
        private readonly Diagnostics $log,
    ) {}

    /**
     * Announce a location whose window will be asked for.
     */
    public function want(string $file, int $line): void
    {
        $this->wanted[$file][$line] = true;
    }

    /**
     * The window around $line of $file, or null when the file cannot be read.
     */
    public function window(string $file, int $line): ?SourceWindow
    {
        if (! isset($this->windows[$file]) || ! array_key_exists($line, $this->windows[$file])) {
            $this->wanted[$file][$line] = true;
            $this->cut($file);
        }

        return $this->windows[$file][$line] ?? null;
    }

    /**
     * Read $file once and cut every window wanted from it.
     */
    private function cut(string $file): void
    {
        $lines = $this->readLines($file);

        foreach (array_keys($this->wanted[$file] ?? []) as $line) {
            $this->windows[$file][$line] = $lines === null ? null : $this->guardedWindowOf($lines, $line);
        }
    }

    /**
     * {@see windowOf()}, with a failure costing that one window. The scrubber
     * is an interface a host may implement, so it is host code called on
     * every window.
     *
     * @param  array<int, string>  $lines
     */
    private function guardedWindowOf(array $lines, int $line): ?SourceWindow
    {
        try {
            return $this->windowOf($lines, $line);
        } catch (Throwable $failure) {
            $this->log->warning('Ranetrace could not cut a source window', [
                'exception' => $failure->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * @return array<int, string>|null
     */
    private function readLines(string $file): ?array
    {
        if ($file === '' || str_contains($file, "eval()'d code")
            || (str_contains($file, '://') && ! str_starts_with($file, 'phar://'))) {
            return null;
        }

        try {
            if (! @is_file($file) || ! @is_readable($file)) {
                return null;
            }

            $size = @filesize($file);

            if ($size === false || $size >= self::MAX_SOURCE_FILE_BYTES) {
                return null;
            }

            $lines = @file($file);
        } catch (Throwable $failure) {
            $this->log->warning('Ranetrace could not read a source file', [
                'exception' => $failure->getMessage(),
            ]);

            return null;
        }

        return is_array($lines) ? $lines : null;
    }

    /**
     * @param  array<int, string>  $lines
     */
    private function windowOf(array $lines, int $line): SourceWindow
    {
        // Clamped at the start of the file, so line 3 shows lines 1 to 11.
        $start = max(0, $line - self::LINES_BEFORE - 1);

        $lookbehindStart = max(0, $start - self::LOOKBEHIND_LINES);
        $lookbehind = $start - $lookbehindStart;

        $window = $this->scrubbedLines(array_values(array_slice($lines, $lookbehindStart, $lookbehind + self::WINDOW_LINES)), $lookbehind);

        $context = $this->dedent(implode('', $window));

        // Each window line holds no newline but its last character, so the
        // dedented text splits back into one entry per line, plus an empty
        // one when the last line ended in a newline.
        $dedented = explode("\n", $context);

        if (count($dedented) > count($window)) {
            array_pop($dedented);
        }

        return new SourceWindow($start + 1, $window === [] ? [] : $dedented, $context);
    }

    /**
     * Repair the lines of a window and the $lookbehind lines given above it,
     * scrub them together, then drop the lookbehind and cap each window line,
     * preserving every trailing newline so the line structure survives. The
     * cap guards against a minified or generated line bloating the item.
     *
     * @param  list<string>  $lines
     * @return list<string>
     */
    private function scrubbedLines(array $lines, int $lookbehind): array
    {
        if (count($lines) <= $lookbehind) {
            return [];
        }

        $contents = [];
        $newlines = [];

        foreach ($lines as $line) {
            $line = Utf8::repair($line);
            $newlines[] = str_ends_with($line, "\n") ? "\n" : '';
            $contents[] = mb_rtrim($line, "\n");
        }

        $scrubbed = array_values($this->scrubber->scrubSource($contents));

        if (count($scrubbed) !== count($contents)) {
            throw new UnexpectedValueException('The scrubber returned '.count($scrubbed).' lines for a window of '.count($contents));
        }

        $window = [];

        foreach (array_slice($scrubbed, $lookbehind, preserve_keys: true) as $index => $content) {
            if (mb_strlen($content) > self::MAX_LINE_LENGTH) {
                $content = mb_substr($content, 0, self::MAX_LINE_LENGTH).self::TRUNCATION_SUFFIX;
            }

            $window[] = $content.$newlines[$index];
        }

        return $window;
    }

    /**
     * Right-trim every line and strip the smallest indentation they share, so a
     * snippet from deep inside a nested method does not arrive as a column of
     * whitespace with code hiding off to the right.
     */
    private function dedent(string $code): string
    {
        $lines = array_map(mb_rtrim(...), explode("\n", $code));

        $minimumIndent = null;

        foreach ($lines as $line) {
            if (mb_trim($line) === '') {
                continue;
            }

            $indent = mb_strlen($line) - mb_strlen(mb_ltrim($line));

            if ($minimumIndent === null || $indent < $minimumIndent) {
                $minimumIndent = $indent;
            }
        }

        if ($minimumIndent === null || $minimumIndent === 0) {
            return implode("\n", $lines);
        }

        foreach ($lines as $index => $line) {
            if (mb_trim($line) !== '') {
                $lines[$index] = mb_substr($line, $minimumIndent);
            }
        }

        return implode("\n", $lines);
    }
}
