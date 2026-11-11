<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use Ranetrace\Php\Config;

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
 * Two things it cannot tell. A deployment that serves the project through a
 * symlink can name a second path for the same directory. And a URL path that
 * happens to start with the root (`GET /app/users` on a host whose root is
 * `/app`) reads as a file under it.
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

    public function __construct(
        private readonly Config $config,
    ) {}

    public function strip(string $text): string
    {
        $pattern = $this->pattern();

        if ($pattern === false || $text === '') {
            return $text;
        }

        // A null is PCRE giving up. The text is kept: what is at stake is a
        // path, and the secrets in the text are the scrubber's to remove.
        return preg_replace_callback($pattern, self::replacement(...), $text) ?? $text;
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

    private function pattern(): string|false
    {
        if ($this->pattern !== null) {
            return $this->pattern;
        }

        $root = $this->config->get('project_root');
        $root = is_scalar($root) ? mb_rtrim((string) $root, '/\\') : '';

        // Nothing left, or a bare drive letter, is the filesystem root. A
        // relative root (`app`) would be found in every text that holds the
        // word, so only an absolute one is looked for.
        if ($root === '' || preg_match('#^(?:[/\\\\]|[A-Za-z]:[/\\\\]).#', $root) !== 1) {
            return $this->pattern = false;
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

        return $this->pattern = '#'.$before.implode(self::SEPARATOR, $segments).$after.'#';
    }
}
