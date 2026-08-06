<?php

declare(strict_types=1);

namespace Ranetrace\Php\Http;

use Throwable;

/**
 * The bundled transport: one cURL POST, no retries, no exceptions.
 *
 * Retrying belongs one layer up. `ranetrace/ranetrace-laravel` learned this the
 * hard way: an in-request retry loop multiplies the time a worker spends inside
 * a send, and the buffer already makes delivery at-least-once, so a failed batch
 * simply goes back on the spool and drains on the next run. Everything here is
 * therefore single-shot.
 *
 * Redirects are not followed on purpose. The request carries a bearer token, and
 * following a redirect would hand that token to whatever host the redirect names.
 */
final class CurlHttpClient implements HttpClientInterface
{
    public function post(string $url, array $headers, string $body, int $connectTimeout, int $timeout): RawResponse
    {
        try {
            return $this->execute($url, $headers, $body, $connectTimeout, $timeout);
        } catch (Throwable $failure) {
            return RawResponse::transportFailure($failure->getMessage());
        }
    }

    /**
     * @param  array<string, string>  $headers
     * @return array<int, string>
     */
    private static function formatHeaders(array $headers): array
    {
        $formatted = [];

        foreach ($headers as $name => $value) {
            $formatted[] = $name.': '.$value;
        }

        return $formatted;
    }

    /**
     * @param  array<string, string>  $headers
     */
    private function execute(string $url, array $headers, string $body, int $connectTimeout, int $timeout): RawResponse
    {
        $handle = curl_init();

        if ($handle === false) {
            return RawResponse::transportFailure('Could not initialise cURL');
        }

        /** @var array<string, string> $responseHeaders */
        $responseHeaders = [];

        curl_setopt_array($handle, [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => self::formatHeaders($headers),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => max(1, $connectTimeout),
            CURLOPT_TIMEOUT => max(1, $timeout),
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$responseHeaders): int {
                // cURL requires the BYTE count of the processed line; a
                // character count would abort the transfer on any multibyte
                // header value, so this must stay '8bit'.
                $length = mb_strlen($line, '8bit');
                $separator = mb_strpos($line, ':');

                if ($separator !== false) {
                    $name = mb_strtolower(mb_trim(mb_substr($line, 0, $separator)));
                    $responseHeaders[$name] = mb_trim(mb_substr($line, $separator + 1));
                }

                return $length;
            },
        ]);

        $responseBody = curl_exec($handle);
        $errorNumber = curl_errno($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);

        if ($errorNumber !== 0 || ! is_string($responseBody)) {
            $message = curl_error($handle);

            return RawResponse::transportFailure($message === '' ? 'cURL request failed' : $message);
        }

        // No curl_close(): CurlHandle objects release the handle when they go
        // out of scope, and the function is deprecated.
        return new RawResponse($status, $responseBody, $responseHeaders);
    }
}
