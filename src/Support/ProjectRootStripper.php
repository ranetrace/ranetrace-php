<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use Ranetrace\Php\Config;
use Throwable;

/**
 * Takes the project root off every path under it in free-form text, so the
 * layout of the server does not leave the host inside a message, a trace or a
 * source line: `/var/www/app/resources/views/a.blade.php` becomes
 * `resources/views/a.blade.php`. A field that holds one path and nothing else
 * (`file`, a frame's `file`) is made relative where it is built; this is for
 * the text around a path.
 *
 * The root is `project_root`, matched byte for byte, and only where a path
 * starts: after the start of the text or a character that cannot be part of a
 * path. So a root of `/app` leaves `/var/app/x.php` and `/application/x.php`
 * alone. Each separator of the root matches `/` or `\`, single or doubled and
 * with the backslash JSON puts before a `/`, so a Windows path, a path in a
 * string literal and a path inside encoded JSON are all found.
 *
 * The root named on its own, with nothing under it, has no relative path to
 * become and is replaced by {@see ROOT_MARKER}.
 *
 * A root that is empty, relative or the filesystem root strips nothing: the
 * first two say no place, and every absolute path starts with the third.
 *
 * It fails soft: a strip that cannot run returns the text as written. What is
 * at stake here is a path, the secrets in the text are the scrubber's to
 * remove after it, and a capture must never be lost to this. A pattern PCRE
 * cannot compile is given up on for good, since PCRE says so with a warning
 * on every attempt, which a host whose error handler throws on warnings turns
 * into an exception.
 *
 * Three things it cannot tell. A deployment that serves the project through a
 * symlink can name a second path for the same directory. The known place this
 * happens is the console script path, which is the path as it was typed:
 * `Errors\PayloadBuilder` resolves that one before the strip, and any other
 * text naming the symlinked path is sent as written. A URL path that happens
 * to start with the root (`GET /app/users` on a host whose root is `/app`)
 * reads as a file under it. And with `zend.exception_ignore_args` off, a frame
 * line of `getTraceAsString()` holds the call's string arguments cut to 15
 * characters, so a root passed as one reads `('/home/forge/sit...')`, a start
 * of the root that matches no path.
 */
final class ProjectRootStripper
{
    /**
     * What the root itself becomes when it is named with nothing under it.
     */
    public const string ROOT_MARKER = '[project root]';

    /**
     * A separator of the root as text can spell it: `/`, `\/`, `\` or `\\`.
     */
    private const string SEPARATOR = '(?:\\\\?/|\\\\\\\\?)';

    /**
     * The pattern for this root, false when the root strips nothing, null
     * until it is built.
     */
    private string|false|null $pattern = null;

    /**
     * @param  Diagnostics|null  $log  Told once when the pattern cannot be used, by a caller that has one.
     */
    public function __construct(
        private readonly Config $config,
        private readonly ?Diagnostics $log = null,
    ) {}

    public function strip(string $text): string
    {
        if ($text === '' || $this->pattern === false) {
            return $text;
        }

        try {
            $pattern = $this->pattern ??= $this->buildPattern();

            if ($pattern === false) {
                return $text;
            }

            $stripped = preg_replace_callback($pattern, self::replacement(...), $text);
        } catch (Throwable $failure) {
            return $this->giveUp($text, $failure->getMessage());
        }

        if ($stripped !== null) {
            return $stripped;
        }

        // An internal error is a pattern that did not compile, on a host that
        // let the warning pass. Any other null is PCRE giving up on this one
        // text, which says nothing about the next.
        return preg_last_error() === PREG_INTERNAL_ERROR ? $this->giveUp($text, preg_last_error_msg()) : $text;
    }

    /**
     * @param  list<string>  $lines
     * @return list<string>
     */
    public function stripLines(array $lines): array
    {
        return array_map($this->strip(...), $lines);
    }

    /**
     * Every string value at any depth, keys left as they are.
     */
    public function stripDeep(mixed $data): mixed
    {
        if (is_string($data)) {
            return $this->strip($data);
        }

        if (is_array($data)) {
            foreach ($data as $key => $value) {
                $data[$key] = $this->stripDeep($value);
            }
        }

        return $data;
    }

    /**
     * A path under the root loses the root and the separator after it; the
     * root on its own becomes the marker.
     *
     * @param  array<array-key, string>  $match
     */
    private static function replacement(array $match): string
    {
        return ($match['under'] ?? '') !== '' ? '' : self::ROOT_MARKER;
    }

    /**
     * Stop stripping for the life of this instance and hand the text back.
     */
    private function giveUp(string $text, string $reason): string
    {
        $this->pattern = false;

        $this->log?->warning('Ranetrace could not take the project root off the paths in a text, so paths are sent as written.', [
            'error' => $reason,
        ]);

        return $text;
    }

    private function buildPattern(): string|false
    {
        $root = $this->config->get('project_root');
        $root = is_scalar($root) ? mb_rtrim((string) $root, '/\\') : '';

        // Nothing left, or a bare drive letter, is the filesystem root. A
        // relative root (`app`) would be found in every text that holds the
        // word, so only an absolute one is looked for.
        if ($root === '' || preg_match('#^(?:[/\\\\]|[A-Za-z]:[/\\\\]).#', $root) !== 1) {
            return false;
        }

        $segments = array_map(
            static fn (string $segment): string => preg_quote($segment, '#'),
            preg_split('#[/\\\\]#', $root) ?: [$root],
        );

        // Before the root: not the tail of a longer name or path. A `/` there
        // is only the one that ends a URL scheme (`file:///var/www/app`).
        $before = '(?<![\w.\-~])(?<!(?<!:/)/)';

        // After it: a separator and a path under it, or the end of the root
        // as a name, with or without a trailing separator.
        $after = '(?:(?<under>'.self::SEPARATOR.')(?=[^\s"\'`)\]},;:<>|\\\\/])'
            .'|'.self::SEPARATOR.'?(?![\w\-~]|\.\w))';

        return '#'.$before.implode(self::SEPARATOR, $segments).$after.'#';
    }
}
