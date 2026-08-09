# Changelog

All notable changes to `ranetrace-php` will be documented in this file.

This file starts here, so releases before it are not recorded; the git history is the record for those.

## [Unreleased]

### Security
- URL values inside breadcrumbs, log context and event properties are now recognised by their **shape** rather than by an `http(s)://` prefix. Previously a relative URL passed through untouched, so a signed download link recorded as `/exports/42/download?expires=…&signature=…` shipped its signature while the identical absolute URL was redacted. The shape test is deliberately strict — no whitespace, none of the characters that only turn up in prose, JSON and code, and a query that is a run of `key=value` pairs — because the redaction rewrites everything from the first `?`, and a looser test would truncate a JSON log-context payload mid-structure. A value that fails the test is left byte-for-byte alone
- `SecretScrubber::scrubDeep()` takes the host's declared sensitive path segments and redacts them inside URL-shaped values, so a reset link the tracker recorded as a navigation breadcrumb loses its `{token}` the same way the top-level `url` field already did. Without it the same payload redacted the secret in one field and shipped it in another. A path segment carries no marker saying it holds a token and this SDK has no router to ask, so the values stay the caller's to supply: `Relay` and `EventTracker` pass whatever was given to their `setSensitivePathValues()`, and passing nothing keeps the previous query-only behaviour. The Monolog handler has no such channel, so log context is still query-only
- The JavaScript error `message` is scrubbed the way the sibling `stack` field already was. The bundled snippet's `unhandledrejection` handler `JSON.stringify`s the rejection value into `message`, so a rejected API response carrying an `api_key` reached the backend in full while the same text inside `stack` was redacted
- The JavaScript error relay's `timestamp` and `breadcrumbs.*.timestamp` fields are capped at 64 characters. They had no length rule and nothing downstream bounded them, so an unauthenticated client could buffer an item limited only by `post_max_size` — large enough to draw a 413 that discards the whole batch and pauses JavaScript error capture

### Known issues
- `SecretScrubber::scrubString()` backtracks super-linearly on a long word-character run containing many sensitive fragments, and a PCRE limit failure returns the input unscrubbed rather than redacting it. Both are shared with `ranetrace/ranetrace-laravel` and unfixed in either
