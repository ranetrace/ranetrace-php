<?php

declare(strict_types=1);

/**
 * A stand-in for the Ranetrace API, as a router for PHP's built-in server, for
 * the tests that run a binary in a subprocess and need an answer to read.
 *
 * It answers every batch of one item with a 200 that counts the item as
 * processed, except for the endpoint path named in FAKE_API_REFUSES, whose
 * item it counts as failed: the answer the real API gives an item that fails
 * its field rules.
 */
$path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
$refused = getenv('FAKE_API_REFUSES');
$counter = is_string($refused) && $refused !== '' && str_ends_with($path, $refused) ? 'failed' : 'processed';

header('Content-Type: application/json');

echo json_encode(['success' => true, 'items' => ['received' => 1, 'processed' => 0, $counter => 1]]);
