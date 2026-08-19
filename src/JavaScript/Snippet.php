<?php

declare(strict_types=1);

namespace Ranetrace\Php\JavaScript;

use InvalidArgumentException;
use Ranetrace\Php\Config;
use RuntimeException;

/**
 * Renders the browser capture script as an inline `<script>` tag.
 *
 * This class is the plain-PHP host's side of the split: it turns
 * {@see Config} into the runtime config the script reads, and asks
 * {@see CaptureScript} for the script itself. The script is shared with
 * `ranetrace/ranetrace-laravel`, which builds its own config from Laravel's
 * config repository and takes the same body from the same class.
 *
 * Two things the Laravel version can discover for itself have to be told to this
 * one. The endpoint is required, because this SDK registers no routes and the
 * host mounts {@see Relay} wherever it likes. The nonce is passed in, because
 * there is no Vite integration to ask for one.
 *
 * There is deliberately no `csrfToken` in the emitted config: this SDK's relay
 * verifies Origin/Referer instead of a CSRF token, so the script is given no
 * token and sends no `X-CSRF-TOKEN` header.
 */
final class Snippet
{
    public function __construct(private readonly Config $config) {}

    /**
     * The `<script>` tag to place before `</body>`, or an empty string when
     * JavaScript error tracking is off.
     *
     * @param  array{endpoint?: string, nonce?: string|null}  $options  `endpoint` is the absolute or root-relative URL the host mounted the relay on. `nonce` is the CSP nonce, when the host uses one.
     *
     * @throws InvalidArgumentException When `endpoint` is missing or empty.
     * @throws RuntimeException When the script template cannot be read, which means a broken install.
     */
    public function render(array $options = []): string
    {
        if (! $this->config->enabled('javascript_errors')) {
            return '';
        }

        $endpoint = $options['endpoint'] ?? null;

        if (! is_string($endpoint) || $endpoint === '') {
            throw new InvalidArgumentException(
                'Ranetrace javascript snippet requires an `endpoint` option: the URL your application '.
                'mounted the Ranetrace JavaScript error relay on.'
            );
        }

        $nonce = $options['nonce'] ?? null;
        $attribute = is_string($nonce) && $nonce !== ''
            ? ' nonce="'.htmlspecialchars($nonce, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8').'"'
            : '';

        return '<script'.$attribute.'>'.PHP_EOL.CaptureScript::withConfig($this->runtimeConfig($endpoint)).PHP_EOL.'</script>';
    }

    /**
     * The runtime config the browser script reads.
     *
     * @return array{endpoint: string, enabled: bool, sampleRate: float, captureConsoleErrors: bool, maxBreadcrumbs: int, ignoredErrors: array<int, string>}
     */
    private function runtimeConfig(string $endpoint): array
    {
        $ignored = $this->config->get('javascript_errors.ignored_errors', Config::DEFAULT_IGNORED_JAVASCRIPT_ERRORS);

        if (! is_array($ignored)) {
            $ignored = Config::DEFAULT_IGNORED_JAVASCRIPT_ERRORS;
        }

        $sampleRate = $this->config->get('javascript_errors.sample_rate', 1.0);
        $maxBreadcrumbs = $this->config->get('javascript_errors.max_breadcrumbs', 20);

        return [
            'endpoint' => $endpoint,
            'enabled' => true,
            'sampleRate' => is_numeric($sampleRate) ? (float) $sampleRate : 1.0,
            'captureConsoleErrors' => $this->config->get('javascript_errors.capture_console_errors') === true,
            'maxBreadcrumbs' => is_numeric($maxBreadcrumbs) ? (int) $maxBreadcrumbs : 20,
            'ignoredErrors' => array_values(array_map(
                static fn (mixed $pattern): string => is_scalar($pattern) ? (string) $pattern : '',
                $ignored,
            )),
        ];
    }
}
