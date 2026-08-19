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

Everything in flight is listed here:

- **The error item's `laravel_version`.** The backend still allow-lists it and normalises it to `framework` plus `framework_version`. `items/errors.json` carries it under `legacy_fields`, not under `fields`. It comes off the allow-list once no deployed Laravel SDK sends it.
- **The log item's `extra` vocabulary.** This SDK attaches `environment`, `php_version` and, when the host names one, `framework` and `framework_version`. The Laravel SDK still reports `laravel_version` there. `extra` is free-shape at ingest, so this one is a convention between the SDKs rather than a validated shape, and it can move without a backend release.

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
