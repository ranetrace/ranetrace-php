# Wire contract changelog

## What this file is

The coordination log for changes to the Ranetrace wire contract. Three codebases have to agree on it:

- `ranetrace/ranetrace-php`, this package, the framework-agnostic PHP SDK.
- `ranetrace/ranetrace-laravel`, the Laravel SDK.
- The Ranetrace backend application, which owns the ingest endpoints.

The fixtures next to this file describe the contract as it stands. This file records how it got there and what is still in flight.

## The iron rule

**The backend must accept a new shape before either SDK ships it.**

The ingest endpoints validate every item in a batch before processing any of it, and the errors endpoint additionally allow-lists its field set. One wrong key in one item fails the whole batch with a 422. The client's response matrix then drops every item in that batch and pauses the feature for fifteen minutes. There is no additive-field tolerance and no partial acceptance, so an SDK that ships a field the backend has not learned yet does not degrade, it goes dark.

That makes the ordering non-negotiable:

1. The backend learns the new shape and is deployed.
2. The SDK that emits it is released.
3. Once every deployed client sends the new shape, the backend's compatibility branch for the old one is retired, as its own change.

A change that only widens what the backend accepts can ship on its own. A change to what an SDK emits cannot.

## How to use it

One entry per coordinated change, newest first. An entry names what moved, why, and carries a status per side:

- `APPLIED` with a date, meaning it is in that codebase's main branch and, for the backend, deployed.
- `PENDING`, meaning it is not, and what breaks until it is.

Verify a status against the code before you trust it. A status is a claim about another repository, and claims go stale; every one below was re-read against the backend's controllers on 2026-08-19 and several had to be corrected.

## Current state

The fixtures beside this file are the source of truth, not the prose below:

- `items/errors.json`, `items/events.json`, `items/logs.json`, `items/javascript_errors.json`: the per-type field spec, transcribed from the backend's validators, with a minimal and a full example that really pass them.
- `envelope.json`: the request body shape, the buffered item shape, and the batch and per-item budgets.
- `endpoints.json`: path and wrapper key per type.
- `headers.json`: the five request headers.
- `responses.json`: the client's response matrix and the response bodies.

Four changes are in flight. The error item's `exception_context` (2026-10-02): its backend side has to be deployed before this package is released with it. The browser name and version in the JavaScript error item's `browser_info` (2026-09-30): its backend side has to be deployed before this package is released with it. The typed `user_id` on the JavaScript error item (2026-09-30): backend only, with nothing for either SDK to do. The allow-listed `user` on the error and event items (2026-10-01): the backend side and this package's narrowing of the error item's `user` can ship in either order. Every other coordinated change below is applied on both sides.

## Change log

### 2026-10-02, the error item carries the throwable's own context as `exception_context`

Status: **backend PENDING, SDK applied in this package.** The backend's `ErrorsBatchController` accepts `exception_context` as null or an array (a JSON object or a list) of at most 100 top-level keys, at most 5 levels deep (a flat `{"a": 1}` is one level) and at most 16,384 bytes JSON-encoded, and adds it to `ALLOWED_ERROR_FIELDS`. It is in its main branch but not yet deployed. Grouping is unchanged: type, file, line and environment. **This package must not be released until that backend is deployed**: the errors endpoint allow-lists its field set, so a deployed backend that does not know the key rejects every error batch with a 422, and error tracking goes dark for every host on the release. `ranetrace/ranetrace-laravel` builds its error items through the shared `Errors\PayloadBuilder`, so it sends the key on its first `composer update` after the release, and it has to allow the key wherever it filters the item's fields before then.

A throwable can carry a public `context()` method returning an array: Laravel's exceptions do, and so can any a developer writes, with the ids and the input that tripped it. Laravel's log reporter merges it into the log entry, and the error item dropped it. The item goes from 19 keys to 20. The wire key `context` was already the source snippet, hence the name. `Errors\PayloadBuilder::build()` reads it from the throwable itself, not from `Errors\ErrorContext`, which holds only what a throwable does not carry, so neither SDK needs adapter code for it. A missing, non-public, throwing, non-array or empty `context()` sends null, and a throwing one costs the context and never the error.

The SDK holds the value tighter than the backend, as headroom: objects, closures and resources are flattened by `Support\DataSanitizer`, secret keys and secrets in URL values are masked by the scrubber, at most 50 top-level keys are kept, a value nested past 3 levels becomes `[Max depth exceeded]`, string values are cut to 500 characters, and trailing top-level keys are dropped until the JSON encoding is at most 8,192 bytes, with null when not even the first key fits or when the value cannot be encoded at all. `items/errors.json` describes the field and carries it in its `full` example; the fixture lint in `tests/Contract/DescriptorValidator.php` learned `max_depth` and `max_json_bytes`, its spelling of the backend's two custom bounds.

### 2026-10-01, the error and event items' `user` carries only the keys the SDKs send

Status: **backend PENDING, SDK applied in this package.** The backend's `ErrorsBatchController` validates `user` as null or an object with only the keys `id` and `email` (`'user' => 'nullable|array:id,email'`), with `user.id` required whenever `user` is not null, as an integer or a string of at most 255 characters, and `user.email` as a nullable string of at most 255 characters with no address-format check. Its `EventsBatchController` validates `user` as null or an object with only the key `id`, typed the same way. Both are in its main branch but not yet deployed; until then any array still passes. The same rule (`App\Rules\SdkUserId`) now also types the JavaScript error item's `user_id`. In this package, `Support\UserId` holds the backend's bound, and every builder checks the host's id against it: `Errors\PayloadBuilder` sends no `user` unless the resolver reports an int, or a string of at most 255 characters, and sends `email` only when it is a string of at most 255 characters, null otherwise; `Events\EventItemBuilder` sends no `user` for any other id; `JavaScript\ErrorItemBuilder` sends a `user_id` string past 255 characters as null. The two shared builders are where `ranetrace/ranetrace-laravel` passes its own auth identifier, so its event and JavaScript error items get the same check on its first `composer update` after the release, with no change of its own.

The two fields were validated as any array with any values, so a nested object, a boolean id or an arbitrary extra key passed and was stored with the error occurrence or the event. They are now allow-listed like the rest of the item: a key outside the list, a wrongly typed `id` or `email`, or a `user` without an `id` fails its item, and with it the whole batch, with a 422. The email is deliberately not checked as an address, because the SDK sends whatever the host's user record holds and one odd address would otherwise cost every batch that user appears in. `items/errors.json` and `items/events.json` replace their `user.*` entry with `user.id` (the union type from the 2026-09-30 entry below) and, for errors, `user.email`; the fixture lint in `tests/Contract/DescriptorValidator.php` learned `keys`, its spelling of Laravel's `array:id,email`.

This narrows what the backend accepts, which the iron rule does not cover on its own. It is safe to ship alone because it narrows only to the shape every emitter sends: both SDKs, and older `ranetrace/ranetrace-laravel` versions from before this shared core, send the error item's `user` as null or `{id, email}` and the event item's as null or `{id}`. What a released SDK can still produce that the backend now rejects is only a value the host itself reports out of bounds: an id that is not an int or a string, or a string id or email past 255 characters. With this package's release, no SDK sends one: the item is sent without the user, or without the email, instead. That change only ever sends less, so it is safe in any release order.

### 2026-09-30, the JavaScript error item's `user_id` is an integer or a string

Status: **backend PENDING, no SDK change needed.** The backend's `JavaScriptErrorsBatchController` validates `user_id` as null, an integer, or a string of at most 255 characters, in its main branch but not yet deployed. Until then it still takes any value. Both SDKs already send exactly that shape: `JavaScript\ErrorItemBuilder::build()` takes the host's user id as `int|string|null`, and `ranetrace/ranetrace-laravel` builds its items through it.

The field had no type at ingest, so an array, a boolean or a nested object passed and was stored in the error's context. It is now typed like every other field: a wrongly typed `user_id` fails its item, and with it the whole batch, with a 422. `items/javascript_errors.json` gives the field `"type": ["integer", "string"]` with `"max": 255`, the contract's first union type; the fixture lint in `tests/Contract/DescriptorValidator.php` learned the list form, with the bound applying to the string member only.

This narrows what the backend accepts, which the iron rule does not cover on its own. It is safe to ship alone because it narrows only to what every emitter already sends: no supported SDK can produce a value the new rule rejects.

### 2026-09-30, the JavaScript error item's `browser_info` carries the browser name and version

Status: **backend PENDING, SDK applied in this package.** The backend is learning `'browser_info.name' => 'nullable|string|max:50'` and `'browser_info.version' => 'nullable|string|max:20'` now and deploys before this package is released with the change. `ranetrace/ranetrace-laravel` builds its JavaScript error items through the shared `JavaScript\ErrorItemBuilder`, so it starts sending the two keys on its first `composer update` after that release, with no change of its own.

`browser_info` goes from seven keys to nine: the seven the browser reports, then `name` and `version`. The backend's JavaScript error page shows a browser pill from exactly these two values, and no SDK sent them. They are derived on the server from the user agent the host observed, never read from the browser payload, for the same reason `user_agent` itself is: a browser can claim anything, so a payload's own `name` or `version` is dropped like every other unknown key. `name` is one of six fixed display names and `version` is digits with at most one dot, both null when the user agent names no known browser, belongs to a crawler, or is absent. `items/javascript_errors.json` describes the two fields and carries them in its `full` example.

Until the backend is deployed, the JavaScript errors endpoint is not strict about its field set and drops a key it has no rule for, so a release that went out early would lose the two values rather than have its batches rejected. The ordering still holds, because a dropped value is a silent gap on the dashboard.

### 2026-08-21, the `laravel_version` error-item spelling is retired at ingest

Status: **APPLIED on both sides.** The backend's `ALLOWED_ERROR_FIELDS` and validator no longer know the key and no longer normalise it; an item carrying it is rejected like any other unknown key. Both SDKs had already moved to the generic `framework` plus `framework_version` pair (the PHP SDK from its first release, the Laravel SDK in its 1.0.0 release built on this core), so no supported emitter sends it. `items/errors.json` dropped its `legacy_fields` block the same day. A pre-1.0 Laravel SDK still deployed somewhere will have its error batches rejected with a 422 until it is upgraded; that is the intended cut.

### 2026-08-21, the log item's `extra` vocabulary is shared

Status: **APPLIED on both sides.** The Laravel SDK attaches `environment`, `php_version`, `framework` and `framework_version` through the shared log builder; its old `laravel_version` extra key is retired. `extra` is free-shape at ingest, so the backend needed no change.

## Archive: the Laravel SDK's backend-changes log

Moved here on 2026-08-19 from `ranetrace-laravel/.claude/backend-changes-needed.md`, which is retired. Every round below was recorded as "applied in client, backend pending" at the time; each has now been re-read against the backend's real controllers and the status corrected. **All four rounds are applied on both sides.** Nothing in this section is outstanding; it is kept because the reasoning behind each shape is here and nowhere else.

### Round 2, error item field set and field types

Status: **APPLIED on both sides.** Corrected on 2026-08-19, was recorded as backend pending. Verified against `ErrorsBatchController::ALLOWED_ERROR_FIELDS` and its validator rules.

Two fields were dropped from the error item:

1. `for`, always the literal string `ranetrace` (legacy `sorane`). An undocumented discriminator with no current purpose.
2. `console_options`, always null in every payload the client ever sent. The value-add over `console_command` plus `console_arguments` was nil; the capture spec openly described it as a placeholder.

Two fields changed from a JSON-encoded string to a proper nested value:

- `headers`, from `string` to an object of `header-name` to `array<string>`. Values are an array because HTTP allows duplicate headers. Bounded client-side at 50 headers and 500 characters per value, with non-allowlisted header values replaced by `["***"]`.
- `console_arguments`, from `string` to `array<string>`. Bounded client-side at 50 entries of at most 500 characters.

The backend now validates both as arrays (`headers.*` array, `headers.*.*` string max 500; `console_arguments.*` string max 500) and neither `for` nor `console_options` appears on its allow-list, so an item carrying either is rejected.

### Round 6, pre-flight batch size guard

Status: **RESOLVED in the client, no backend change was ever required.** Unchanged from the original record.

Oversize 413s are prevented client-side by trimming the serialized batch to a 4.5MB budget and re-buffering the tail. Both SDKs do it; `envelope.json` carries the numbers.

### Round 7, `type` in the body of the MCP single-error endpoints

Status: **APPLIED on both sides.** Corrected on 2026-08-19, was recorded as backend pending. Verified against `Api\V1\Mcp\ErrorActionsController`, which reads the discriminator with `$request->input('type', 'php')`. `input()` reads the JSON body as well as the query string, so both the new body-carried spelling and the old `?type=` continue to work.

PHP errors and JavaScript errors live in separate tables with independent auto-increment ids, so the same numeric id exists in both and the discriminator is mandatory rather than cosmetic. The id prefix is authoritative: `err_` for PHP, `jserr_` for JavaScript, and a wrong `type` selects the wrong table.

One residue worth knowing: the backend still defaults a missing `type` to `php` rather than rejecting the request. The client compensates by requiring an explicit `type` in its MCP tools and refusing an id whose prefix contradicts it. `getErrorActivity` was never changed; it is a GET and the discriminator legitimately belongs in its query string.

### Round 10, error item timestamp rename

Status: **APPLIED on both sides.** Corrected on 2026-08-19, was recorded as backend pending. Verified against the errors validator, which requires `timestamp` as a date; `time` is not on the allow-list, so an item still sending it is rejected.

The error item's timestamp was the only capture type using its own key and format. It moved from `"time": "2025-10-06 15:30:45"` to `"timestamp": "2025-10-06T15:30:45+00:00"`, which is what logs, events, page visits and JavaScript errors already used.

### Round 11, error item switches to the generic framework pair

Status: **APPLIED on both sides.** Verified on 2026-08-19 against `ALLOWED_ERROR_FIELDS` and the normalisation in `processErrorReport()`.

`laravel_version` was replaced by `framework` plus `framework_version`, taking the item from 18 fields to 19. The backend accepts both spellings: `laravel_version` normalises to framework `laravel`, and an explicit generic pair wins when both arrive. The generic pair is what a framework-agnostic SDK can honestly state, and it is what `items/errors.json` describes as canonical. Retiring the legacy branch is the follow-up, and it waits on every deployed Laravel SDK sending the pair.
