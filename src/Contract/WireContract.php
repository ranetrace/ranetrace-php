<?php

declare(strict_types=1);

namespace Ranetrace\Php\Contract;

use InvalidArgumentException;
use RuntimeException;

/**
 * Reads the wire-contract fixtures shipped in `contract/` at the package root.
 *
 * The fixtures, not this class, are the artifact: they are plain JSON so the
 * sibling Laravel SDK and the backend application can read the same files
 * through their own vendor directory and test against one description of the
 * wire instead of three drifting ones. This class exists so a PHP consumer does
 * not have to know the layout or repeat the decoding, and {@see basePath()} so a
 * non-PHP consumer (or a test that wants the raw file) can still find them.
 *
 * Every reader throws. A missing or malformed fixture is a packaging fault, not
 * a runtime condition: the SDK's silent-capture posture protects the host from
 * telemetry failures, and this class is never on a capture path.
 */
final class WireContract
{
    /**
     * The four item types, in the order the buffer and the worker use.
     *
     * @var list<string>
     */
    private const array ITEM_TYPES = ['errors', 'events', 'logs', 'javascript_errors'];

    /**
     * @return list<string>
     */
    public static function itemTypes(): array
    {
        return self::ITEM_TYPES;
    }

    /**
     * One item type's field spec and examples.
     *
     * @return array<string, mixed>
     *
     * @throws InvalidArgumentException When the type is not one of {@see itemTypes()}.
     */
    public static function item(string $type): array
    {
        if (! in_array($type, self::ITEM_TYPES, true)) {
            throw new InvalidArgumentException(
                "Unknown Ranetrace item type '{$type}'. Known types: ".implode(', ', self::ITEM_TYPES).'.'
            );
        }

        return self::read('items/'.$type.'.json');
    }

    /**
     * @return array<string, mixed>
     */
    public static function envelope(): array
    {
        return self::read('envelope.json');
    }

    /**
     * @return array<string, mixed>
     */
    public static function endpoints(): array
    {
        return self::read('endpoints.json');
    }

    /**
     * @return array<string, mixed>
     */
    public static function headers(): array
    {
        return self::read('headers.json');
    }

    /**
     * @return array<string, mixed>
     */
    public static function responses(): array
    {
        return self::read('responses.json');
    }

    /**
     * Absolute path of the `contract/` directory, so a consuming repository can
     * locate the files through its own `vendor/`.
     */
    public static function basePath(): string
    {
        return dirname(__DIR__, 2).'/contract';
    }

    /**
     * @return array<string, mixed>
     *
     * @throws RuntimeException When the fixture is missing, unreadable, or not a JSON object.
     */
    private static function read(string $relativePath): array
    {
        $file = self::basePath().'/'.$relativePath;

        if (! is_file($file) || ! is_readable($file)) {
            throw new RuntimeException("Ranetrace wire contract fixture is missing or unreadable: {$file}");
        }

        $contents = file_get_contents($file);

        if (! is_string($contents)) {
            throw new RuntimeException("Ranetrace wire contract fixture could not be read: {$file}");
        }

        $decoded = json_decode($contents, true);

        if (! is_array($decoded)) {
            throw new RuntimeException("Ranetrace wire contract fixture is not valid JSON: {$file}");
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
