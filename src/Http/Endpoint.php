<?php

declare(strict_types=1);

namespace Ranetrace\Php\Http;

/**
 * Everything the transport has to know about one capture type: where its batch
 * goes, which key the body wraps it under, which feature name the User-Agent
 * attributes it to, and which config key holds its timeout.
 *
 * Shared with `ranetrace/ranetrace-laravel`, which reads the same table rather
 * than keeping its own copy of these strings. Paths are kebab-case and wrapper
 * keys snake_case, and the two spellings of `javascript_errors` are the whole
 * reason this is a lookup rather than a naming rule.
 *
 * The SDK name is NOT stored here. It is per SDK, not per endpoint, so it is
 * supplied at the call site: this package sends `Ranetrace-PHP/...`, the Laravel
 * SDK `Ranetrace-Laravel/...`, from one shared feature name.
 *
 * `$timeoutKey` is a dot key relative to the SDK's own config root, so the
 * Laravel SDK prefixes it with `ranetrace.` and this one does not. The logs type
 * reads `logging.timeout` because the config section is named for the feature,
 * not for the buffer.
 */
final readonly class Endpoint
{
    public function __construct(
        public string $type,
        public string $path,
        public string $wrapper,
        public string $feature,
        public string $timeoutKey,
    ) {}

    /**
     * The per-SDK, per-feature User-Agent, e.g. `Ranetrace-PHP/Errors/1.0`.
     *
     * @param  string  $sdk  The `{SDK}` segment, e.g. `PHP` or `Laravel`.
     */
    public function userAgent(string $sdk): string
    {
        return 'Ranetrace-'.$sdk.'/'.$this->feature.'/'.EndpointTable::USER_AGENT_VERSION;
    }
}
