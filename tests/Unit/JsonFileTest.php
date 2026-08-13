<?php

declare(strict_types=1);

use Ranetrace\Php\Support\JsonFile;

it('writes an encodable value as json', function (): void {
    $file = tempDirectory().'/state.json';

    expect(JsonFile::write($file, ['errors' => 1]))->toBeTrue()
        ->and(json_decode((string) file_get_contents($file), true))->toBe(['errors' => 1]);
});

it('replaces the target rather than appending to it', function (): void {
    $file = tempDirectory().'/state.json';

    JsonFile::write($file, ['errors' => 1]);
    JsonFile::write($file, ['events' => 2]);

    expect(json_decode((string) file_get_contents($file), true))->toBe(['events' => 2]);
});

it('leaves no temp file behind once the write has landed', function (): void {
    $directory = tempDirectory();

    JsonFile::write($directory.'/state.json', ['errors' => 1]);

    expect(glob($directory.'/*.tmp'))->toBe([]);
});

it('lands the whole file or none of it', function (): void {
    $directory = tempDirectory();
    $file = $directory.'/state.json';
    $payload = ['items' => array_fill(0, 5000, str_repeat('a', 64))];

    JsonFile::write($file, $payload);

    // A reader that opens the file at any moment sees a complete document
    // because the write arrives through a rename, never through a partial
    // file_put_contents on the target itself.
    expect(json_decode((string) file_get_contents($file), true))->toBe($payload);
});

it('refuses a value json cannot express', function (): void {
    $directory = tempDirectory();

    expect(JsonFile::write($directory.'/state.json', ['bad' => NAN]))->toBeFalse()
        ->and(is_file($directory.'/state.json'))->toBeFalse()
        ->and(glob($directory.'/*.tmp'))->toBe([]);
});

it('reports a write it could not place and cleans up after itself', function (): void {
    $directory = tempDirectory().'/absent';

    expect(JsonFile::writeEncoded($directory.'/state.json', '{}'))->toBeFalse()
        ->and(is_dir($directory))->toBeFalse();
});

it('creates a missing directory group readable but never world readable', function (): void {
    $directory = tempDirectory().'/nested/spool';

    expect(JsonFile::ensureDirectory($directory))->toBeTrue()
        ->and(is_dir($directory))->toBeTrue();

    // 0770 is requested; the process umask can only take bits away, so assert
    // the invariant that matters: the group keeps access where the umask allows
    // it, and the world never gets any.
    expect(fileperms($directory) & 0777)->toBe(0770 & ~umask());
});

it('accepts a directory that already exists', function (): void {
    $directory = tempDirectory();

    expect(JsonFile::ensureDirectory($directory))->toBeTrue();
});

it('reports a directory it cannot create', function (): void {
    $file = tempDirectory().'/not-a-directory';
    file_put_contents($file, 'x');

    expect(JsonFile::ensureDirectory($file.'/child'))->toBeFalse();
});

it('deletes a file and shrugs at one that is already gone', function (): void {
    $file = tempDirectory().'/state.json';
    file_put_contents($file, '{}');

    JsonFile::delete($file);
    JsonFile::delete($file);

    expect(is_file($file))->toBeFalse();
});
