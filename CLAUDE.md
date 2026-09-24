# Working on ranetrace-php

## What this package is

`ranetrace/ranetrace-php` is the framework-agnostic PHP SDK for Ranetrace. It captures errors, log records, custom events and browser JavaScript errors, buffers them to a local file spool, and a worker ships them to the Ranetrace API in batches.

It is a **library**, not an application. No framework, no container, no globals beyond the ones a plain PHP host already has. Everything it needs to know about its host arrives through `Ranetrace\Php\Config`: the environment name, the project root, the framework identity, how to resolve the current user. If you find yourself wanting to detect something about the host, add a config key instead.

This file is for working **on** the package. An agent working in an application that merely uses it wants `AGENTS.md` at the repo root: the config table, the required wiring and the pitfalls, with none of the internals below. Keep the two in step when the public surface changes.

Its sibling is `ranetrace/ranetrace-laravel` (working copy at `../ranetrace-laravel`), which does the same job inside Laravel. Several classes here are direct ports from it and say so in their docblock. **A port's semantics must not drift.** If you change what one of them does, the two SDKs start producing different payloads for the same input, and the difference will surface as backend validation failures rather than as a test failure here.

## The wire contract is sacred

The Ranetrace API does **strict field-set matching**: a payload with an extra key, a missing key or a wrong type gets the **whole batch** rejected with a 422, which drops every item in it and pauses the feature for fifteen minutes. There is no additive-field tolerance and no partial acceptance.

The contract is written down in `contract/`, which ships with the package so the Laravel SDK and the backend application can test against the same artifact rather than three drifting descriptions of it:

- `contract/items/*.json` per capture type: the field spec transcribed from the backend's own validators, plus a minimal and a full example that really pass them.
- `contract/envelope.json`, `endpoints.json`, `headers.json`, `responses.json`: the body shape and budgets, the paths and wrapper keys, the five headers, and the client's response matrix.
- `Contract\WireContract` reads them; `tests/Contract` asserts that the emitters, the worker and the API client still agree with them.

So:

- Never add, rename, remove or retype a key in a payload the API receives without the backend accepting the new shape **first**.
- Changing what an emitter sends means changing the matching fixture in the same commit. If the fixture cannot change yet because the backend has not moved, the emitter cannot change yet either.
- Coordinated changes go in `contract/CHANGELOG.md`, one entry with a status per side, and ship in lockstep with the backend task.
- `Ranetrace-API-Version: 1.0` goes on every request.
- The tests assert exact payload shapes on purpose. A test that has to be edited to accommodate a payload change is the alarm working, not a chore.

## House rules

- **PHP 8.4**, `declare(strict_types=1)` in every file, explicit parameter and return types everywhere, constructor property promotion, curly braces even for one-line bodies.
- **Spatie's Laravel and PHP guidelines** apply, minus the Laravel-specific parts. This repo installs no skills of its own: read `../ranetrace-laravel/.claude/skills/spatie-laravel-php-standards/SKILL.md` before writing PHP.
- PHPDoc over inline comments. Array shapes in PHPDoc. Inline comments only where the logic is genuinely surprising.
- **Record the reasoning behind non-obvious decisions where the next maintainer will hit them**: in the docblock, in the test name, in the commit message. A rule with no recorded reason gets refactored away by someone who assumes it was arbitrary.
- Run `vendor/bin/pint` before finishing. Run `vendor/bin/phpstan analyse` too.

## Releasing

- When you tag `vX.Y.Z`, move everything under `## [Unreleased]` in `CHANGELOG.md` to a new `## [X.Y.Z] - YYYY-MM-DD` heading in the commit the tag points at, and leave an empty `## [Unreleased]` above it. A tag without its own heading is a release nobody can read about: v1.0.1 to v1.0.3 shipped with every entry still under `[Unreleased]`.

## The browser capture script is a committed pair

`resources/js/error-tracker.js` is the readable source and the only file to edit. `resources/js/error-tracker.min.js` is its generated twin, and it is what `JavaScript\CaptureScript` reads, because that body is inlined into every page view of every site that installs either SDK, and the twin is under a third of the source's size, under half once gzipped. `composer build-js` prints the current figures.

- Edit the source, then run `composer build-js` (`bin/build-capture-script`). It runs the pinned esbuild command, refuses to stamp an output that fails its checks, and writes `resources/js/build-manifest.json`.
- The twin is committed rather than built on install because Composer runs no JavaScript toolchain and a consumer must never need node. That is also why `bin/build-capture-script`, `package.json` and the lockfile are `export-ignore`d while everything under `resources/js` ships.
- The manifest stamps the sha256 of **both** files, so an edit to either without a rebuild fails the suite with the command to run. That guard is a hash comparison precisely so it needs no toolchain: the suite runs everywhere, the build runs only on a maintainer's machine.
- The esbuild version is pinned in `package.json` and in the build script, because a different version can emit different bytes. `npm install` here gets it; without a local install the script falls back to `npx --yes esbuild@<version>`.
- **Minification renames every local variable and function.** Nothing outside the source may identify the script by a local name or by a phrase that lives only in a comment. Key on string literals, property names, `window` members, the endpoint or the config keys. `JavaScriptCaptureScriptTest` guards the source and may read its own spelling; `JavaScriptCaptureScriptBuildTest` guards the twin and is the model for anything new.

## Tests

- **Pest, functional style only.** `test('it does the thing', function (): void { ... })`. No class-based PHPUnit tests anywhere in the suite.
- `composer test` runs the suite in parallel. `vendor/bin/pest --filter=...` for a narrow run.
- Every change is programmatically tested. Before fixing a bug, write the test that reproduces its root cause, then make it pass.
- Capture paths must never throw into the host. Test the failure isolation, not just the happy path.

## Failure posture

Two postures live side by side here, and the split is deliberate:

- **Configuration errors are loud.** A non-string API key or a non-callable user resolver throws from the `Config` constructor. The developer can still fix these, and silence would leave them with an SDK that quietly captures nothing.
- **Capture failures are silent.** Anything that happens while reporting an error, writing a log record or tracking an event is caught, written to the internal diagnostics log, and dropped. Monitoring must never be the reason an application breaks.

`Support\InternalLogger` is the diagnostics sink and is deliberately isolated from the capture path. It writes to its own file, never through the host's logger. If SDK diagnostics went through a logger the host had routed back into Ranetrace, a failing send would log a failure that gets captured, buffered and sent, which fails again.

## Writing prose

Applies to the README, docblocks, commit messages and anything else a human reads:

- No em-dashes.
- Sentence case for headings and labels. No all-caps eyebrows.
- Say the thing plainly. Claim only what the code actually does.
