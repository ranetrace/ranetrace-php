<?php

declare(strict_types=1);

namespace Ranetrace\Php\JavaScript;

use InvalidArgumentException;
use Ranetrace\Php\Config;
use RuntimeException;

/**
 * Renders the browser capture script as an inline `<script>` tag.
 *
 * Ported from `ranetrace/ranetrace-laravel`'s `error-tracker.blade.php`, which
 * was one file mixing the script with Blade interpolation. Here the script lives
 * on its own at `resources/js/error-tracker.js` with a single
 * `__RANETRACE_CONFIG__` token, and this class substitutes the JSON config into
 * it. Splitting them is what lets the script be linted, diffed against the
 * Laravel original, and asserted on by a test.
 *
 * Two things the Laravel version could discover for itself have to be told to
 * this one. The endpoint is required, because this SDK registers no routes and
 * the host mounts {@see Relay} wherever it likes. The nonce is passed in,
 * because there is no Vite integration to ask for one.
 *
 * There is deliberately no `csrfToken` in the emitted config: the relay verifies
 * Origin/Referer instead of a CSRF token, so the script has no token to carry.
 */
final class Snippet
{
    /**
     * The one token the template exposes. Changing it here without changing the
     * template ships an unconfigured script that silently does nothing.
     */
    private const string CONFIG_TOKEN = '__RANETRACE_CONFIG__';

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

        return '<script'.$attribute.'>'.PHP_EOL.$this->script($endpoint).PHP_EOL.'</script>';
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

    /**
     * The template with its config token substituted.
     *
     * @throws RuntimeException
     */
    private function script(string $endpoint): string
    {
        $template = @file_get_contents($this->templatePath());

        if ($template === false) {
            throw new RuntimeException('Unable to read the Ranetrace JavaScript error tracker template at '.$this->templatePath().'.');
        }

        // JSON_HEX_TAG/AMP/APOS keep a `</script>` or a stray quote inside a
        // config value (an endpoint, an ignored-error pattern) from closing the
        // tag we are inlining into. JSON_HEX_QUOT is deliberately NOT set: it
        // would escape the structural double quotes too, and `"` outside a
        // string is not valid JavaScript. JSON_PRESERVE_ZERO_FRACTION keeps a
        // sample rate of 1.0 spelled as a float, so the emitted config reads as
        // what it is.
        $json = (string) json_encode(
            $this->runtimeConfig($endpoint),
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION,
        );

        return str_replace(self::CONFIG_TOKEN, $json, $template);
    }

    private function templatePath(): string
    {
        return dirname(__DIR__, 2).'/resources/js/error-tracker.js';
    }
}
