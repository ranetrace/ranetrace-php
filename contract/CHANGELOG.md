# Wire contract changelog

## What this file is

The coordination log for changes to the Ranetrace wire contract. Three codebases have to agree on it:

- `ranetrace/ranetrace-php`, this package, the framework-agnostic PHP SDK.
- `ranetrace/ranetrace-laravel`, the Laravel SDK.
- The Ranetrace backend application, which owns the ingest endpoints.

The fixtures next to this file describe the contract as it stands. This file records how it got there and what is still in flight.

## The iron rule

**The backend must accept a new shape before either SDK ships it.**

The ingest endpoints validate every item on its own, and the errors endpoint additionally allow-lists its field set. One wrong key in an item refuses that item: the server does not store it and counts it as failed, which the client treats as final. There is no additive-field tolerance, and an SDK puts the same keys on every item of a type, so an SDK that ships a field the backend has not learned yet does not degrade, it goes dark: every item of that type it sends is refused.

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

Two changes are in flight. The 2026-11-13 entry that gives the error item an `id`: the backend accepts the field in its main branch and has not deployed it; this package's main branch sends it and is not released, and `ranetrace/ranetrace-laravel` waits on that release. Until the backend deploy, neither SDK may release it, because the errors endpoint refuses every error item that carries the key. The 2026-11-13 entry that retires three event checks: the backend's main branch has dropped them and is not deployed, `items/events.json` no longer lists them, and nothing breaks in the meantime, because it only widens what the backend accepts. The 2026-11-13 entry that gives the event item and the JavaScript error item an `id` is released in this package's 1.4.0, and `ranetrace/ranetrace-laravel` sends it from 1.5.0, which requires that release; the backend deployed its half the same day. That Laravel release is also the first to send a page visit without its `url`. The 2026-11-13 console event entry is released in this package's 1.3.0, and `ranetrace/ranetrace-laravel` sends it from 1.4.0, which requires that release. The two 2026-11-12 entries are released in this package's 1.2.0 and in `ranetrace/ranetrace-laravel` 1.3.0, which requires it. The backend had nothing to do for any of the three. Every other coordinated change below is applied on both sides: the backend deployed the six before them on 2026-10-16, and this package's 1.1.0 is the first release to send the error item's `frames`, `frames_omitted` and `previous`.

## Change log

### 2026-11-13, the events endpoint stops refusing an event for its name or its property values

Status: **PENDING on the backend: its main branch has the change, and it is not deployed. Nothing to do for either SDK beyond the fixture.** This only widens what the backend accepts, so by the iron rule it ships on its own, in any order, and nothing breaks meanwhile: until the deploy, an event that trips one of the three checks is refused as before.

The events endpoint refused an event for three reasons beside its field rules and its size: an event name of `test`, `bot_action`, `fake_event` or `debug`, a property value that accounted for more than 80 percent of the event's values, and a string property value that repeated one character more than 50 times in a row. The sender is the website's own server, and the checks refused honest events: a `debug` event, a set of flags that are all `true`, a separator line of dashes. A refused event is counted `failed`, which is final, and the SDK's internal log holds only the count, so the event was lost without a trace. The backend dropped all three.

The two size checks stay: the JSON encoding of the whole item at most 5,120 bytes, and a top-level string property value at most 500 characters. The backend now counts that 500 in characters, where it counted bytes and so refused a 300-character Greek string.

`items/events.json` removes `forbidden_event_names`, `max_property_repetition_ratio` and `max_consecutive_character_repetition` from `additional_checks`, and the note of `max_property_value_chars` says it counts characters. Neither SDK checked the three: an event name is held only to the field's pattern and length.

### 2026-11-13, the error item carries an `id`

Status: **PENDING on the backend: its main branch accepts the field, and it is not deployed. Unreleased in `ranetrace/ranetrace-php`, whose main branch sends it. `ranetrace/ranetrace-laravel` sends it once it requires the release that carries it and allows the key in `HandleErrorJob`, which its main branch does.** The order is the iron rule's, and here it is strict: the errors endpoint allow-lists its fields, so an SDK that sends `id` to a backend that has not deployed it has every error item refused, and refused is final. Neither SDK may release this until the backend deploy is done.

The backend counts an error report it does not store (an identical report within 5 minutes, or one its spike guard holds back) as an occurrence of its error, where it lost such a report before. A batch that the backend stored, whose answer never reached the client, is kept by the client and sent again 60 to 900 seconds later. Without an id of its own each error report in it would then be counted a second time: one more occurrence for an error that happened once.

The error item now carries `id`, a UUID the SDK makes once, in `Errors\PayloadBuilder::build()` when the error is captured, on the model of the event item. It is part of the item, so it stays the same through a queue job that runs twice, a put-back into the spool and every later send. A previous exception inside the item carries no id: it is part of its item, not a report of its own. `ranetrace/ranetrace-laravel` builds its error items through the shared builder before it queues the capture job, and adds `id` to the allow-list of `HandleErrorJob`.

The backend takes `id` as optional, a UUID when present, and does not store it. It holds the id per website for 30 minutes and counts an error item whose id it has already handled as `ignored`, neither stored nor counted again. An item without one, from an SDK older than the field, has no resend check. A value that is not a UUID refuses the item.

`items/errors.json` declares the field, describes it in its notes and carries it in its `full` example; the `minimal` example stays without it, as an older SDK sends it. The error item goes from 23 keys to 24.

### 2026-11-13, the event item and the JavaScript error item carry an `id`

Status: **APPLIED on both sides. Backend deployed 2026-11-13, the event half first and the JavaScript error half before this package's release. Released in `ranetrace/ranetrace-php` 1.4.0. `ranetrace/ranetrace-laravel` sends it from 1.5.0, which requires that release.** The order was the iron rule's: the backend deploy came first, then this package's release, then the Laravel SDK's. Neither endpoint allow-lists its fields, so an SDK that sends the `id` to a backend that does not know it loses no item: the key is dropped and the item is handled as before.

A batch that the backend stored, whose answer never reached the client, is kept by the client and sent again 60 to 900 seconds later. The backend has to recognise those items or store them twice. For events it compared fields (name, timestamp, URL, both hashes, properties, user), and two events alike in every field within one second, as a counter tracked twice in a loop of a console process is, were read as one event sent twice: the second was counted `ignored` and lost. For JavaScript errors it had no check at all, so a batch sent again stored every report a second time and an error counted two occurrences for one.

Both items now carry `id`, a UUID the SDK makes once: `Events\EventItemBuilder::build()` when the event is captured, `JavaScript\ErrorItemBuilder::build()` when the relay receives the report, never from the browser payload. It is part of the item, so it stays the same through a queue job that runs twice, a put-back into the spool and every later send. The spool envelope's own `id` is a different thing: client bookkeeping that never reaches the API, and in the Laravel SDK it is made after the capture job has left the queue, so a job that ran twice would give one capture two of them. `ranetrace/ranetrace-laravel` builds both items through the shared builders and adds `id` to the allow-lists of its two capture jobs.

The backend validates `id` as `nullable|uuid` on both endpoints and does not store it. It claims a cache key of the website and the id for 30 minutes before it stores the item, which outlives the longest gap before a client's next attempt. A key that is held means a resend, counted `ignored`. An item that was not stored releases its key, so its resend is stored. An event without an id, from an SDK older than the field, is still compared by its fields. A JavaScript error item without an id has no check, as before: two reports alike in every field are two occurrences. A value that is not a UUID refuses the item.

`items/events.json` and `items/javascript_errors.json` declare the field, describe it in their notes and carry it in their `full` example; the `minimal` examples stay without it, as an older SDK sends them. The event item goes from seven keys to eight and the JavaScript error item from fifteen to sixteen. Log items get no id: at log volume a cache key per record for 30 minutes is real memory, and a lost answer is rare. That is open to change when doubled log records are reported.

### 2026-11-10, a page visit's `url` is optional, and the Laravel SDK stops sending it

Status: **APPLIED on the backend, deployed 2026-11-10. `ranetrace/ranetrace-laravel` stops sending the key from 1.5.0. Nothing to do for this package, which sends no page visits.** The backend required `url` on a page visit and then dropped it, because a visit keeps its `path` and has no column for a URL. The rule is `nullable` now, so the Laravel SDK sends a visit without the key. The page visit item has no fixture here, because only the Laravel SDK emits it.

### 2026-11-10, the backend stops storing a batch after 8 seconds

Status: **APPLIED on the backend, deployed 2026-11-10. No SDK change needed.** The backend stops storing a batch 8 seconds after the request reached it, where it took up to 60, and names the items it did not reach in `unprocessed_indexes`, which both SDKs already put back for the next run. The 8 seconds are tied to the SDKs' default request timeout of 10 seconds and must stay under it: a client that gives up on a batch the server is still storing keeps the whole batch and sends it again, and everything stored meanwhile lands twice. `responses.json` records the deadline under `statuses.200`, and the SDKs' documentation says to keep a timeout at 8 seconds or more. The same deploy made every non-200 of the API answer with the `error_body` shape, the 401 of a rejected key and the 429 of the route throttle included, which `responses.json` already stated; both SDKs now write that message to their internal log for a 429 as they did for the other statuses.

### 2026-11-13, an event from a console process sends `session_id_hash` and `user_agent_hash` as null

Status: **APPLIED, released in `ranetrace/ranetrace-php` 1.3.0. `ranetrace/ranetrace-laravel` sends it from 1.4.0, which requires that release. Nothing to do for the backend.** No rule moved: `items/events.json` gives both fields as optional and, when present, a string of 64 characters, which is the backend's `nullable|string|size:64`. What moved is the emitters, for an event tracked from a command, a scheduled task or a queued job.

A console process has no visitor, and the two SDKs said so in two different ways. This package sent a null `user_agent_hash` and a `session_id_hash` built from an empty address, an empty user agent and the date. The Laravel SDK read the request Laravel makes up for a console process, whose user agent is the word `Symfony` and whose address is `127.0.0.1`, and sent the hash of each. Either way every console event of one installation on one day shared one session hash, and the backend counts the session hashes of events without a user as visitors, so a day of scheduled events counted as one active user. Both SDKs now send null for both fields in a console process: `Events\EventTracker` here, `Ranetrace::buildEventPayload()` there, and `Events\EventItemBuilder::build()` takes a nullable session hash. An event tracked in a request carries both hashes as before, and a page visit is not affected.

The deployed backend was read on 2026-11-13 (`09e7ca94c`): the rule for both fields is `nullable|string|size:64`, both columns are nullable, the per-session burst check runs only for a session hash of 64 characters, and the duplicate check hashes a null like any other value. So there is no order to keep: the backend accepts the old and the new value. What changes for its reader is the count: console events without a user are no longer one visitor a day. `items/events.json` says so in its notes.

### 2026-11-12, an event without a user agent sends `user_agent_hash` as null

Status: **APPLIED, released in `ranetrace/ranetrace-php` 1.2.0. `ranetrace/ranetrace-laravel` sends it from 1.3.0, which requires that release. Nothing to do for the backend.** The field's rule did not move: `items/events.json` already gave it as optional and, when present, a string of 64 characters, which is the backend's `nullable|string|size:64`. What moved is the emitter. An event tracked with no user agent, as every event from a console process is, went out with `user_agent_hash: ""`, which that rule refuses. It was accepted only because the backend runs Laravel's `ConvertEmptyStringsToNull` middleware before it validates, so the two sides agreed by way of a step neither had written down. `Support\FingerprintGenerator::generateUserAgentHash()` now returns null for a missing user agent and `Events\EventItemBuilder` passes it on, so the item matches the fixture as it leaves the SDK. `items/events.json` says so in its notes.

The backend stores the same either way, null, and its duplicate check hashes the same value, so there is no order to keep: an SDK that sends null and one that still sends the empty string are both accepted. Checked on 2026-11-12 with `bin/ranetrace-test` against the backend's main branch: the event was accepted and stored with a null `user_agent_hash`. The deployed backend was re-read on 2026-11-13, before the release: its rule for the field is the same `nullable|string|size:64`. A page visit is not affected, because the Laravel SDK never tracks a request without a user agent, and `session_id_hash` is always a hash.

### 2026-11-12, a client without an API key sends nothing and pauses nothing

Status: **APPLIED, released in `ranetrace/ranetrace-php` 1.2.0 and in `ranetrace/ranetrace-laravel` 1.3.0; nothing to do for the backend.** No request or response shape moved. What changed is what a client does when it has no key: `responses.json` gains a top-level `without_api_key` statement, and its `network` row no longer lists a missing key among the causes of status 0. The backend never sees a keyless client either way, so it has nothing to do. `ranetrace/ranetrace-laravel` follows the same statement: its batch job takes nothing from the buffer without a key, and `ranetrace:work` dispatches nothing and says the key is missing while items wait.

A plain PHP site often loads its key from `.env` in its own bootstrap, so the web process has the key and a cron flush that reads only the environment does not. The keyless flush took the waiting items, the API client answered status 0 without sending, the worker read that as a network failure, re-buffered the items and wrote a 15 minute feature pause into the pause store the web process shares, so the process that has the key was paused too. `Worker::run()` now returns before it takes any item when the key is blank, writes one warning to the internal log when something waits, and neither reads nor sets a pause; `vendor/bin/ranetrace-flush` says the key is missing on stderr and exits 1. `ApiClient::sendBatch()` keeps its own blank-key guard and its status 0 answer for a direct caller of `Worker::send()`. `tests/Contract/TransportConformsTest.php` pins the worker to the statement: with a blank key and a waiting item, no request, the item still buffered with its envelope unchanged, and no pause of either scope.

### 2026-10-15, the error item carries structured frames, their source and the previous-exception chain

Status: **APPLIED on both sides.** Backend deployed 2026-10-16, SDK released in 1.1.0. The backend's `ErrorsBatchController` accepts three new keys and adds them to `ALLOWED_ERROR_FIELDS`: `frames` (null or a list of at most 50 frame objects), `frames_omitted` (null or an integer of at least 0, null exactly when `frames` is) and `previous` (null or a list of 1 to 5 previous-exception objects). A frame allow-lists `index`, `file`, `line`, `class`, `function`, `type`, `is_vendor` and `source`; a source allow-lists `start_line` and `lines` (1 to 11 strings of at most 2,015 characters, a blank one arriving as null); a previous exception allow-lists `type`, `message`, `file`, `line`, `source`, `frames` and `frames_omitted`. Indexes are distinct and strictly increasing within a list, and a vendor frame with a non-null `source` refuses the item. `items/errors.json` states every rule, and its `full` and `console` examples carry frames, sources, a previous exception and a nonzero `frames_omitted`. The release waited for that backend, as the iron rule requires: the errors endpoint allow-lists its field set, so a backend that did not know the keys would have refused every error item. `ranetrace/ranetrace-laravel` builds its error items through the shared `Errors\PayloadBuilder`, so it sends the keys on its first `composer update` after the release, and it has to allow them wherever it filters the item's fields before then.

The item goes from 20 keys to 23. Every existing key, `trace`, `context` and `highlight_line` among them, keeps its shape; the `context` lines are now secret-scrubbed, which changes values, not the shape. The SDK never reads a trace frame's `args`, so no argument value can travel. Source lines are on by default and switched off with `errors.capture_source` (`RANETRACE_ERRORS_CAPTURE_SOURCE=false`), which also nulls `context` and `highlight_line`. Over the per-item byte budget an error item sheds its sources, then its middle frames, then its previous exceptions before the generic per-field cut runs, and that cut never touches `frames` or `previous`: `envelope.json`'s `client_item_policy` says so.

### 2026-10-07, an invalid item is refused on its own, not with its batch

Status: **APPLIED, backend deployed 2026-10-16; no SDK change needed.** The backend's five batch ingest controllers validate each item as strictly as before, but an item that fails validation, including one that is not an object at all, no longer fails its batch with a 422. It is not stored, it is counted as `failed` in the ordinary 200 response, and the valid items around it are processed as usual. A batch whose every item is invalid answers 200 with `processed` 0. A 422 now means only a request body of the wrong shape: the wrapper key is missing, its value is not a list, or the list is empty. An over-size batch is still a 413.

Both SDKs already treat a `failed` item as final and log it, and the success body keeps its shape and its invariant, so neither needs a release. Before, one malformed item cost the up to 999 items batched with it and paused the feature for fifteen minutes; now it costs that item. `responses.json` describes the 200 and the 422 as they now are, and the item and envelope notes say an invalid item is refused rather than taking its batch down. The notes of `items/errors.json`, `items/logs.json` and `items/javascript_errors.json` also record that `message`, and a breadcrumb's `message`, may be an empty string: the key must be present and a string, which the backend has accepted since it learned to store an exception or a log record without a message.

### 2026-10-02, the error item carries the throwable's own context as `exception_context`

Status: **APPLIED on both sides.** Backend deployed 2026-10-16, SDK released in 1.1.0. The backend's `ErrorsBatchController` accepts `exception_context` as null or an array (a JSON object or a list) of at most 100 top-level keys, at most 5 levels deep (a flat `{"a": 1}` is one level) and at most 16,384 bytes JSON-encoded, and adds it to `ALLOWED_ERROR_FIELDS`. Grouping is unchanged: type, file, line and environment. The release waited for that backend: the errors endpoint allow-lists its field set, so a backend that did not know the key would have refused every error item. `ranetrace/ranetrace-laravel` builds its error items through the shared `Errors\PayloadBuilder`, so it sends the key on its first `composer update` after the release, and it has to allow the key wherever it filters the item's fields before then.

A throwable can carry a public `context()` method returning an array: Laravel's exceptions do, and so can any a developer writes, with the ids and the input that tripped it. Laravel's log reporter merges it into the log entry, and the error item dropped it. The item goes from 19 keys to 20. The wire key `context` was already the source snippet, hence the name. `Errors\PayloadBuilder::build()` reads it from the throwable itself, not from `Errors\ErrorContext`, which holds only what a throwable does not carry, so neither SDK needs adapter code for it. A missing, non-public, throwing, non-array or empty `context()` sends null, and a throwing one costs the context and never the error.

The SDK holds the value tighter than the backend, as headroom: objects, closures and resources are flattened by `Support\DataSanitizer`, secret keys and secrets in URL values are masked by the scrubber, at most 50 top-level keys are kept, a value nested past 3 levels becomes `[Max depth exceeded]`, string values are cut to 500 characters, and trailing top-level keys are dropped until the JSON encoding is at most 8,192 bytes, with null when not even the first key fits or when the value cannot be encoded at all. `items/errors.json` describes the field and carries it in its `full` example; the fixture lint in `tests/Contract/DescriptorValidator.php` learned `max_depth` and `max_json_bytes`, its spelling of the backend's two custom bounds.

### 2026-10-01, the error and event items' `user` carries only the keys the SDKs send

Status: **APPLIED on both sides.** Backend deployed 2026-10-16, SDK released in 1.1.0. The backend's `ErrorsBatchController` validates `user` as null or an object with only the keys `id` and `email` (`'user' => 'nullable|array:id,email'`), with `user.id` required whenever `user` is not null, as an integer or a string of at most 255 characters, and `user.email` as a nullable string of at most 255 characters with no address-format check. Its `EventsBatchController` validates `user` as null or an object with only the key `id`, typed the same way. The same rule (`App\Rules\SdkUserId`) now also types the JavaScript error item's `user_id`. In this package, `Support\UserId` holds the backend's bound, and every builder checks the host's id against it: `Errors\PayloadBuilder` sends no `user` unless the resolver reports an int, or a string of at most 255 characters, and sends `email` only when it is a string of at most 255 characters, null otherwise; `Events\EventItemBuilder` sends no `user` for any other id; `JavaScript\ErrorItemBuilder` sends a `user_id` string past 255 characters as null. The two shared builders are where `ranetrace/ranetrace-laravel` passes its own auth identifier, so its event and JavaScript error items get the same check on its first `composer update` after the release, with no change of its own.

The two fields were validated as any array with any values, so a nested object, a boolean id or an arbitrary extra key passed and was stored with the error occurrence or the event. They are now allow-listed like the rest of the item: a key outside the list, a wrongly typed `id` or `email`, or a `user` without an `id` fails its item, and with it the whole batch, with a 422. The email is deliberately not checked as an address, because the SDK sends whatever the host's user record holds and one odd address would otherwise cost every batch that user appears in. `items/errors.json` and `items/events.json` replace their `user.*` entry with `user.id` (the union type from the 2026-09-30 entry below) and, for errors, `user.email`; the fixture lint in `tests/Contract/DescriptorValidator.php` learned `keys`, its spelling of Laravel's `array:id,email`.

This narrows what the backend accepts, which the iron rule does not cover on its own. It is safe to ship alone because it narrows only to the shape every emitter sends: both SDKs, and older `ranetrace/ranetrace-laravel` versions from before this shared core, send the error item's `user` as null or `{id, email}` and the event item's as null or `{id}`. What a released SDK can still produce that the backend now rejects is only a value the host itself reports out of bounds: an id that is not an int or a string, or a string id or email past 255 characters. With this package's release, no SDK sends one: the item is sent without the user, or without the email, instead. That change only ever sends less, so it is safe in any release order.

### 2026-09-30, the JavaScript error item's `user_id` is an integer or a string

Status: **APPLIED, backend deployed 2026-10-16; no SDK change needed.** The backend's `JavaScriptErrorsBatchController` validates `user_id` as null, an integer, or a string of at most 255 characters. Both SDKs already send exactly that shape: `JavaScript\ErrorItemBuilder::build()` takes the host's user id as `int|string|null`, and `ranetrace/ranetrace-laravel` builds its items through it.

The field had no type at ingest, so an array, a boolean or a nested object passed and was stored in the error's context. It is now typed like every other field: a wrongly typed `user_id` fails its item, and with it the whole batch, with a 422. `items/javascript_errors.json` gives the field `"type": ["integer", "string"]` with `"max": 255`, the contract's first union type; the fixture lint in `tests/Contract/DescriptorValidator.php` learned the list form, with the bound applying to the string member only.

This narrows what the backend accepts, which the iron rule does not cover on its own. It is safe to ship alone because it narrows only to what every emitter already sends: no supported SDK can produce a value the new rule rejects.

### 2026-09-30, the JavaScript error item's `browser_info` carries the browser name and version

Status: **APPLIED on both sides.** Backend deployed 2026-10-16, SDK released in 1.1.0. The backend validates `'browser_info.name' => 'nullable|string|max:50'` and `'browser_info.version' => 'nullable|string|max:20'`. `ranetrace/ranetrace-laravel` builds its JavaScript error items through the shared `JavaScript\ErrorItemBuilder`, so it starts sending the two keys on its first `composer update` after that release, with no change of its own.

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
