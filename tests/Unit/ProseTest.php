<?php

declare(strict_types=1);

/*
 * CLAUDE.md rules out em-dashes in anything a human reads: the README, the
 * changelogs, docblocks, comments and log messages. A prose rule that nothing
 * checks drifts, so the suite checks it. The character is spelled as an
 * escape below so this file does not trip its own test.
 */

/**
 * @return array<int, string>
 */
function proseFiles(): array
{
    $root = dirname(__DIR__, 2);
    $files = glob($root.'/*.md') ?: [];

    foreach (['bin', 'contract', 'resources', 'src', 'tests'] as $directory) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root.'/'.$directory, FilesystemIterator::SKIP_DOTS),
        );

        foreach ($iterator as $file) {
            if ($file instanceof SplFileInfo && $file->isFile()) {
                $files[] = $file->getPathname();
            }
        }
    }

    return $files;
}

test('no file a human reads contains an em-dash', function (): void {
    $root = dirname(__DIR__, 2);
    $offenders = [];

    foreach (proseFiles() as $path) {
        if (str_contains((string) file_get_contents($path), "\u{2014}")) {
            $offenders[] = mb_substr($path, mb_strlen($root) + 1);
        }
    }

    expect($offenders)->toBe([]);
});
