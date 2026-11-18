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
 *
 * A heartbeat is answered with the status in FAKE_API_HEARTBEAT_STATUS, 200
 * when it is not set. With FAKE_API_RECORD set to a file, every request is
 * appended to it as one JSON line, so a test can read what a subprocess sent.
 */
$path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
$record = getenv('FAKE_API_RECORD');

if (is_string($record) && $record !== '') {
    file_put_contents($record, json_encode([
        'path' => $path,
        'user_agent' => (string) ($_SERVER['HTTP_USER_AGENT'] ?? ''),
        'body' => (string) file_get_contents('php://input'),
    ])."\n", FILE_APPEND);
}

if (str_ends_with($path, '/heartbeat')) {
    $status = (int) (getenv('FAKE_API_HEARTBEAT_STATUS') ?: 200);

    http_response_code($status);
    header('Content-Type: application/json');

    echo json_encode($status === 200 ? ['success' => true] : ['success' => false, 'error' => ['message' => 'Heartbeat refused']]);

    return;
}

$refused = getenv('FAKE_API_REFUSES');
$items = is_string($refused) && $refused !== '' && str_ends_with($path, $refused)
    ? ['received' => 1, 'processed' => 0, 'failed' => 1]
    : ['received' => 1, 'processed' => 1];

header('Content-Type: application/json');

echo json_encode(['success' => true, 'items' => $items]);
