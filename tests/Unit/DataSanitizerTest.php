<?php

declare(strict_types=1);

use Ranetrace\Php\Support\DataSanitizer;

test('it sanitizes arrays correctly', function (): void {
    $data = [
        'string' => 'test',
        'number' => 123,
        'bool' => true,
        'null' => null,
    ];

    expect(DataSanitizer::sanitizeForSerialization($data))->toBe($data);
});

test('it replaces closures with placeholder', function (): void {
    $result = DataSanitizer::sanitizeForSerialization([
        'closure' => fn (): string => 'test',
        'normal' => 'value',
    ]);

    expect($result['closure'])->toBe('[Closure]')
        ->and($result['normal'])->toBe('value');
});

test('it handles nested closures', function (): void {
    $result = DataSanitizer::sanitizeForSerialization([
        'nested' => [
            'closure' => fn (): string => 'test',
            'another_closure' => function (): void {
                // do nothing
            },
            'safe_value' => 'test',
        ],
    ]);

    expect($result['nested']['closure'])->toBe('[Closure]')
        ->and($result['nested']['another_closure'])->toBe('[Closure]')
        ->and($result['nested']['safe_value'])->toBe('test');
});

test('it converts objects with toArray method', function (): void {
    $object = new class
    {
        /**
         * @return array<string, string>
         */
        public function toArray(): array
        {
            return ['key' => 'value'];
        }
    };

    expect(DataSanitizer::sanitizeForSerialization($object))->toBe(['key' => 'value']);
});

test('it converts objects with jsonSerialize method', function (): void {
    $object = new class implements JsonSerializable
    {
        /**
         * @return array<string, bool>
         */
        public function jsonSerialize(): array
        {
            return ['serialized' => true];
        }
    };

    expect(DataSanitizer::sanitizeForSerialization($object))->toBe(['serialized' => true]);
});

test('it converts objects with __toString method', function (): void {
    $object = new class
    {
        public function __toString(): string
        {
            return 'string representation';
        }
    };

    expect(DataSanitizer::sanitizeForSerialization($object))->toBe('string representation');
});

test('it handles objects without serialization methods', function (): void {
    expect(DataSanitizer::sanitizeForSerialization(new stdClass))->toContain('stdClass');
});

test('it survives an object whose serialization throws', function (): void {
    $object = new class
    {
        /**
         * @return array<string, string>
         */
        public function toArray(): array
        {
            throw new RuntimeException('nope');
        }
    };

    expect(DataSanitizer::sanitizeForSerialization($object))->toContain('serialization failed');
});

test('it handles resources', function (): void {
    $resource = fopen('php://memory', 'r');

    expect(DataSanitizer::sanitizeForSerialization($resource))->toContain('Resource');

    fclose($resource);
});

test('it preserves primitive values', function (): void {
    expect(DataSanitizer::sanitizeForSerialization('string'))->toBe('string')
        ->and(DataSanitizer::sanitizeForSerialization(123))->toBe(123)
        ->and(DataSanitizer::sanitizeForSerialization(45.67))->toBe(45.67)
        ->and(DataSanitizer::sanitizeForSerialization(true))->toBeTrue()
        ->and(DataSanitizer::sanitizeForSerialization(false))->toBeFalse()
        ->and(DataSanitizer::sanitizeForSerialization(null))->toBeNull();
});

test('it bounds recursion depth instead of overflowing the stack', function (): void {
    // 30 levels deep, beyond MAX_DEPTH (20). Must terminate with a marker
    // rather than recursing to a fatal stack exhaustion.
    $deep = 'leaf';
    for ($i = 0; $i < 30; $i++) {
        $deep = ['nested' => $deep];
    }

    expect(json_encode(DataSanitizer::sanitizeForSerialization($deep)))->toContain('Max depth exceeded');
});

test('it handles deeply nested structures', function (): void {
    $result = DataSanitizer::sanitizeForSerialization([
        'level1' => [
            'level2' => [
                'level3' => [
                    'closure' => fn (): string => 'test',
                    'value' => 'deep',
                ],
            ],
        ],
    ]);

    expect($result['level1']['level2']['level3']['closure'])->toBe('[Closure]')
        ->and($result['level1']['level2']['level3']['value'])->toBe('deep');
});

test('a float JSON cannot spell becomes the string PHP spells it as', function (float $value, string $spelled): void {
    expect(DataSanitizer::sanitizeForSerialization(['value' => $value]))->toBe(['value' => $spelled]);
})->with([
    'infinity' => [INF, 'INF'],
    'negative infinity' => [-INF, '-INF'],
    'not a number' => [NAN, 'NAN'],
]);

test('finite floats JSON can spell keep their type, at both ends of the range', function (): void {
    $data = ['negative_zero' => -0.0, 'huge' => PHP_FLOAT_MAX, 'tiny' => PHP_FLOAT_MIN, 'plain' => 1.5];

    $sanitized = DataSanitizer::sanitizeForSerialization($data);

    expect($sanitized)->toBe($data)
        ->and(json_encode($sanitized))->not->toBeFalse();
});

test('a non-finite float inside an object flattened through jsonSerialize or toArray is spelled too', function (): void {
    $serializable = new class implements JsonSerializable
    {
        /**
         * @return array<string, float>
         */
        public function jsonSerialize(): array
        {
            return ['ratio' => INF];
        }
    };

    $arrayable = new class
    {
        /**
         * @return array<string, float>
         */
        public function toArray(): array
        {
            return ['ratio' => NAN];
        }
    };

    expect(DataSanitizer::sanitizeForSerialization(['a' => $serializable, 'b' => $arrayable, 'c' => [[[INF]]]]))
        ->toBe(['a' => ['ratio' => 'INF'], 'b' => ['ratio' => 'NAN'], 'c' => [[['INF']]]]);
});
