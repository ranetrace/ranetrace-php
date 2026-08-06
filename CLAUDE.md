# Working on ranetrace-php

## What this package is

`ranetrace/ranetrace-php` is the framework-agnostic PHP SDK for Ranetrace. It captures errors, log records, custom events and browser JavaScript errors, buffers them to a local file spool, and a worker ships them to the Ranetrace API in batches.

It is a **library**, not an application. No framework, no container, no globals beyond the ones a plain PHP host already has. Everything it needs to know about its host arrives through `Ranetrace\Php\Config`: the environment name, the project root, the framework identity, how to resolve the current user. If you find yourself wanting to detect something about the host, add a config key instead.

This file is for working **on** the package. An agent working in an application that merely uses it wants `AGENTS.md` at the repo root: the config table, the required wiring and the pitfalls, with none of the internals below. Keep the two in step when the public surface changes.

Its sibling is `ranetrace/ranetrace-laravel` (working copy at `../ranetrace-laravel`), which does the same job inside Laravel. Several classes here are direct ports from it and say so in their docblock. **A port's semantics must not drift.** If you change what one of them does, the two SDKs start producing different payloads for the same input, and the difference will surface as backend validation failures rather than as a test failure here.

## The wire contract is sacred

The Ranetrace API does **strict field-set matching**: a payload with an extra key, a missing key or a wrong type gets the **whole batch** rejected with a 422, which drops every item in it and pauses the feature for fifteen minutes. There is no additive-field tolerance and no partial acceptance.

So:

- Never add, rename, remove or retype a key in a payload the API receives without the backend accepting the new shape **first**.
- Changes that need the backend to move go in the coordination log at `../ranetrace-laravel/.claude/backend-changes-needed.md`, and ship in lockstep with the backend task.
- `Ranetrace-API-Version: 1.0` goes on every request.
- The tests assert exact payload shapes on purpose. A test that has to be edited to accommodate a payload change is the alarm working, not a chore.

## House rules

- **PHP 8.4**, `declare(strict_types=1)` in every file, explicit parameter and return types everywhere, constructor property promotion, curly braces even for one-line bodies.
- **Spatie's Laravel and PHP guidelines** apply, minus the Laravel-specific parts. Activate the `spatie-laravel-php-standards` skill when writing PHP.
- PHPDoc over inline comments. Array shapes in PHPDoc. Inline comments only where the logic is genuinely surprising.
- **Record the reasoning behind non-obvious decisions where the next maintainer will hit them**: in the docblock, in the test name, in the commit message. A rule with no recorded reason gets refactored away by someone who assumes it was arbitrary.
- Run `vendor/bin/pint` before finishing. Run `vendor/bin/phpstan analyse` too.

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
