<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use DateTimeImmutable;
use Ranetrace\Php\Config;

/**
 * Turns raw visitor identifiers into salted, one-way hashes before they leave
 * the host. Ranetrace never receives a raw IP, user agent or session id.
 *
 * Shared with `ranetrace/ranetrace-laravel`, whose copy this replaced. The
 * hashed inputs and their separator are the contract: the session hash is
 * HMAC-SHA256 over `ip|first-100-chars-of-user-agent|Y-m-d`, so it rotates
 * every day and cannot be joined across sites. There is one derivation because
 * two of them stop event and visit records lining up. What differs per host is
 * only where the three inputs come from, which is why they arrive as plain
 * strings rather than as a request object.
 */
final class FingerprintGenerator
{
    public function __construct(private readonly Config $config) {}

    /**
     * Daily-rotating, non-persistent session hash linking a visitor's events
     * within one day. The date is a parameter so callers (and tests) can pin it;
     * it defaults to today in the host's timezone.
     */
    public function generateSessionIdHash(?string $ip, ?string $userAgent, ?string $date = null): string
    {
        $date ??= (new DateTimeImmutable)->format('Y-m-d');

        $raw = ($ip ?? '').'|'.mb_substr($userAgent ?? '', 0, 100).'|'.$date;

        return $this->hash($raw);
    }

    /**
     * Hash of the raw user agent, or an empty string when the request carried
     * none. Empty rather than a hash of '' so the backend can tell "no user
     * agent" from "some user agent we hashed".
     */
    public function generateUserAgentHash(?string $userAgent): string
    {
        return $userAgent === null || $userAgent === '' ? '' : $this->hash($userAgent);
    }

    /**
     * HMAC-SHA256 an arbitrary value with the per-install fingerprint salt. Use
     * to pseudonymise an identifier (e.g. a raw session id) before it leaves the
     * host.
     */
    public function hash(string $value): string
    {
        return hash_hmac('sha256', $value, $this->salt());
    }

    /**
     * Per-install salt for fingerprint HMACs. Defaults to the API key, which
     * every install already has and never transmits in a payload, so hashes are
     * non-reversible out of the box. Set `fingerprint_salt` to rotate
     * fingerprints independently of the key.
     */
    private function salt(): string
    {
        $salt = $this->config->get('fingerprint_salt');

        if (is_string($salt) && $salt !== '') {
            return $salt;
        }

        return $this->config->key();
    }
}
