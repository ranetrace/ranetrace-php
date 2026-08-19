<?php

declare(strict_types=1);

namespace Ranetrace\Php\JavaScript;

use RuntimeException;

/**
 * The browser capture script, with a host's runtime config substituted into it.
 *
 * This is the one source for the script both Ranetrace SDKs serve. The same ~370
 * lines used to live twice, once at `resources/js/error-tracker.js` here and once
 * inline in `ranetrace/ranetrace-laravel`'s `error-tracker.blade.php`. Each SDK's
 * relay validates exactly what its own copy sends, so a fix applied to one copy
 * silently stranded the other, and nothing failed until a browser in production
 * posted a shape the other relay did not accept. The script now lives only here
 * and every host obtains it through this class.
 *
 * The host supplies the whole runtime config, because the two hosts do not build
 * it the same way: this SDK reads {@see \Ranetrace\Php\Config} (see {@see Snippet}),
 * the Laravel SDK reads Laravel's config repository, its router and its session.
 * Anything the script understands may therefore be supplied by either, and a key
 * a host leaves out is simply `undefined` in the browser. That is how `csrfToken`
 * stays a Laravel concern: its relay sits behind CSRF middleware and configures a
 * token, this SDK's relay verifies `Origin`/`Referer` and configures none, and the
 * script sends the `X-CSRF-TOKEN` header only when it was given one.
 *
 * This class deliberately does not wrap the result in a `<script>` tag. The tag's
 * attributes are the host's business: this SDK takes a nonce as an option, the
 * Laravel SDK asks `Vite::cspNonce()` for one.
 */
final class CaptureScript
{
    /**
     * The one token the template exposes. Changing it here without changing the
     * template ships an unconfigured script that silently does nothing.
     */
    private const string CONFIG_TOKEN = '__RANETRACE_CONFIG__';

    /**
     * The script body, ready to be placed inside a `<script>` tag.
     *
     * @param  array<string, mixed>  $config  The runtime config the script reads. `endpoint`, `enabled`, `sampleRate`, `captureConsoleErrors`, `maxBreadcrumbs` and `ignoredErrors` are what it looks for; `csrfToken` is honoured when present.
     *
     * @throws RuntimeException When the script template cannot be read, which means a broken install.
     */
    public static function withConfig(array $config): string
    {
        return str_replace(self::CONFIG_TOKEN, self::encode($config), self::template());
    }

    /**
     * The runtime config as a JavaScript object literal.
     *
     * JSON_HEX_TAG/AMP/APOS keep a `</script>` or a stray quote inside a config
     * value (an endpoint, an ignored-error pattern) from closing the tag the
     * script is being inlined into. JSON_HEX_QUOT is deliberately NOT set: it
     * would escape the structural double quotes too, and `&quot;` outside a
     * string is not valid JavaScript. JSON_PRESERVE_ZERO_FRACTION keeps a sample
     * rate of 1.0 spelled as a float, so the emitted config reads as what it is.
     * JSON_UNESCAPED_SLASHES leaves the endpoint URL readable; the usual reason
     * to escape a slash is `</script>`, and JSON_HEX_TAG already makes that
     * impossible by escaping the `<` itself.
     *
     * @param  array<string, mixed>  $config
     */
    private static function encode(array $config): string
    {
        return (string) json_encode(
            $config,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION,
        );
    }

    /**
     * @throws RuntimeException
     */
    private static function template(): string
    {
        $template = @file_get_contents(self::templatePath());

        if ($template === false) {
            throw new RuntimeException('Unable to read the Ranetrace JavaScript error tracker template at '.self::templatePath().'.');
        }

        return $template;
    }

    private static function templatePath(): string
    {
        return dirname(__DIR__, 2).'/resources/js/error-tracker.js';
    }
}
