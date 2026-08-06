<?php

declare(strict_types=1);

namespace Ranetrace\Php\Tests;

use PHPUnit\Framework\TestCase as BaseTestCase;

/**
 * Base case for the package suite. The SDK has no framework container to boot,
 * so this only exists to give Pest a single place to hang shared behaviour.
 */
abstract class TestCase extends BaseTestCase {}
