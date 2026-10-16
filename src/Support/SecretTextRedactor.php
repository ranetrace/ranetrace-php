<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

use UnexpectedValueException;

/**
 * Finds the secrets in free-form text and in windows of source lines, for
 * {@see SecretScrubber::scrubString()} and {@see SecretScrubber::scrubSource()},
 * which own the sensitive fragment list and what failing closed means. Every
 * method here throws UnexpectedValueException when PCRE gives up.
 *
 * It catches `key=value`, `key: value` and `key => value` pairs whose key
 * holds a sensitive fragment, query-string-like leakage and the arguments of a
 * call whose name holds one or that is on {@see CREDENTIAL_CALLS}, but not a
 * positional secret argument to any other call. A regex finds each key and
 * its separator (the anchor), and the value after it is read by hand, because
 * a code value has to balance brackets and one pattern cannot do that
 * cheaply. See {@see anchorPattern()} for what an anchor is and why the
 * pattern stays linear.
 *
 * The value after an anchor takes one of these shapes:
 *
 * - A quoted value is redacted whole. It runs to its matching closing quote,
 *   past spaces, commas and the other quote, with backslash escapes skipped.
 *   Without a closing quote it runs to the end of the line, never further. An
 *   empty one (`''`) holds nothing and is left alone. A literal joined onto it
 *   with `.` is redacted with it.
 * - In source only, a code value, which keeps its code byte-for-byte and loses
 *   only the bodies of its string literals, since in
 *   `'password' => Hash::make('x')` the literal is the secret and the rest is
 *   what makes the line worth reading. {@see startsCodeValue()} says what
 *   starts one, and {@see redactCodeValue()} where it ends. A literal that
 *   names a lookup, as in `env('DB_PASSWORD', 'x')`, is kept, see
 *   {@see namesLookup()}.
 * - Outside source, an unquoted value is redacted whole, and a bracket in it
 *   is followed to its matching close: `token=(abc)`,
 *   `{"token":{"value":"abc"}}` and `'password' => Hash::make('x')` lose the
 *   value and every literal it holds.
 * - Anything else is a bare token, redacted up to whitespace, a quote or
 *   `,;&)]}`, after an optional `Bearer`, `Basic` or `Digest` scheme that is
 *   kept. `true`, `null`, a number or a constant is a bare token too: it is
 *   redacted, which costs nothing readable and needs no list of literals.
 *
 * @internal
 *
 * @phpstan-type CarriedState array{kind: string, depth: int, quote: string|null}
 */
final class SecretTextRedactor
{
    /**
     * How many characters of a key token may precede the sensitive fragment
     * inside it, in {@see anchorPattern()}. Bounding this is what keeps the
     * pattern's cost linear; see that method for why, and for what it costs.
     */
    private const int MAX_KEY_PREFIX = 64;

    /**
     * What ends a bare token: the whitespace `\s` means, a quote, and the
     * characters that end a pair in a query string, an argument list or an
     * array.
     */
    private const string BARE_VALUE_STOPS = "\"' \t\n\v\f\r,;&)]}";

    /**
     * What a line can leave open for the lines after it in
     * {@see redactSource()}: the value of a key that ended the line, the
     * arguments of a sensitive call, or a code value whose bracket is open.
     * A fallback is the value of a sensitive read that ended the line, and
     * only when the next line starts with `??`, `??=` or `?:`.
     */
    private const string CARRIED_VALUE = 'value';

    private const string CARRIED_FALLBACK = 'fallback';

    private const string CARRIED_CALL = 'call';

    private const string CARRIED_CODE = 'code';

    /**
     * What a carried value's `quote` holds when the line before left a block
     * comment open inside it, rather than a string literal.
     */
    private const string CARRIED_BLOCK_COMMENT = '*/';

    /**
     * The characters that continue a heredoc marker, so `EOT` closes a body
     * and `EOTX` does not.
     */
    private const string NAME_CHARACTERS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';

    /**
     * The fewest base64 characters a line must hold to be taken for the body
     * of a private key in {@see redactPrivateKeyBodies()}. A PEM body line is
     * 64, and the last one of a block is often shorter.
     */
    private const int MIN_KEY_BODY_LINE = 40;

    /**
     * The global functions whose first argument, and the superglobals whose
     * subscript, name where a value lives rather than hold it, see
     * {@see namesLookup()}. Function names are matched case-insensitively, as
     * PHP calls them; superglobals are case-sensitive variables. `getenv`
     * comes before `env`, which it ends in.
     */
    private const array LOOKUP_FUNCTIONS = ['getenv', 'env', 'config'];

    private const array LOOKUP_SUPERGLOBALS = ['$_ENV', '$_SERVER'];

    /**
     * Calls known to take a credential by position, as patterns for their name
     * up to the space before the `(`, read like a sensitive call (see
     * {@see anchorPattern()}). A positional argument carries no key, so nothing
     * but its call can say it is a credential, and a name such as `PDO` or
     * `ftp_login` holds no sensitive fragment. The list is curated and never
     * complete: a call joins it when it is common and takes a credential this
     * way, and only by its whole name. It stays apart from the fragment list
     * because a word like `auth` there would turn every key that starts with it
     * (`author`) and Laravel's `auth('api')` helper into secrets.
     *
     * A constructor appears as `new PDO(` in source and as `PDO->__construct(`
     * in a text trace, where PHP masks only the password parameter.
     */
    private const array CREDENTIAL_CALLS = [
        'new(?:\s++\\\\?+|\\\\)(?:pdo|mysqli)',
        '(?:pdo|mysqli)->__construct',
        'mysqli_connect',
        'mysqli_real_connect',
        'real_connect',
        'ldap_bind',
        'ldap_sasl_bind',
        'ftp_login',
        'ssh2_auth_password',
        'imap_open',
        'withbasicauth',
        'withdigestauth',
    ];

    /**
     * The Laravel validation rules whose name, as the last segment of a quoted
     * dotted key, makes the key name a validation message rather than a value:
     * `'password.required' => 'Vul je wachtwoord in'`. Curated and never
     * complete; a rule missing here costs a readable message, never a secret.
     * The key must be quoted, as a FormRequest's `messages()` writes it, so
     * `token.min=abc` in a query string is still a pair.
     */
    private const array VALIDATION_RULES = [
        'required', 'required_if', 'required_with', 'required_without', 'confirmed',
        'min', 'max', 'size', 'between', 'string', 'regex', 'not_regex', 'same',
        'different', 'current_password', 'alpha', 'alpha_num', 'alpha_dash', 'email',
        'in', 'not_in', 'numeric', 'integer', 'uncompromised', 'mixed_case', 'letters',
        'numbers', 'symbols', 'nullable', 'sometimes', 'filled', 'present', 'prohibited',
        'unique', 'exists', 'lowercase', 'uppercase', 'ascii',
    ];

    /**
     * The constructor call a subclass of `PDO` or `mysqli` passes its
     * credentials on with, read as a {@see CREDENTIAL_CALLS} entry only while
     * {@see redactSource()} reads lines that declare such a subclass. Anywhere
     * else it is most often an exception handing its message on.
     */
    private const string PARENT_CONSTRUCTOR_CALL = 'parent\s*+::\s*+__construct';

    /**
     * {@see anchorPattern()}, built once per instance for each value of
     * {@see $readsCredentialSubclass}.
     *
     * @var array<int, string>
     */
    private array $anchorPatterns = [];

    /**
     * {@see carryPatterns()}, built once per instance for each value of
     * {@see $readsCredentialSubclass}.
     *
     * @var array<int, array{value: string, fallback: string, heredoc: string}>
     */
    private array $carryPatterns = [];

    /**
     * Whether {@see redactSource()} is reading lines that declare a subclass
     * of `PDO` or `mysqli`, see {@see PARENT_CONSTRUCTOR_CALL}.
     */
    private bool $readsCredentialSubclass = false;

    /**
     * Whether {@see scrubComment()} is scrubbing a comment, inside which a
     * comment ends a code value as it does outside a bracket. That keeps the
     * nesting at one level, however many comments a line holds.
     */
    private bool $scrubbingComment = false;

    /**
     * @param  list<string>  $fragments  The sensitive key fragments, lower case.
     */
    public function __construct(
        private readonly array $fragments,
    ) {}

    /**
     * A free-form string, such as a message, a trace, a log record or a
     * command line, with its secrets redacted. An unquoted value is never
     * read as code here, see {@see redactValue()}.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    public function redactString(string $text): string
    {
        return $this->scrubText($text, readsCode: false)[0];
    }

    /**
     * A window of consecutive source lines with its secrets redacted, read as
     * a whole so that a secret spanning lines is caught. Each line is read as
     * {@see redactString()} reads a string, except that an unquoted value can
     * be code, plus what only a run of lines can show:
     *
     * - A value on the next line. A line that ends in a sensitive key and
     *   `=>`, `=`, `.=`, `??=`, `??` or `?:` has the start of the next line
     *   read as that value. Only one line ahead, and never after `:` or a
     *   comparison, so `case 'token':` followed by `return $x;` stays
     *   readable. A line that ends in a sensitive read (`$token`,
     *   `$config['password']`, `input('password')`) whose next line starts
     *   with `??`, `??=` or `?:` has the value after it read the same way.
     * - An open bracket. While the parentheses of a sensitive call, or a
     *   bracket opened inside a code value after a sensitive key, are still
     *   open at the end of a line, the lines after it go on as that value,
     *   literals redacted and code kept, until the bracket closes or the
     *   window ends. An unclosed bracket costs only the literals after it.
     * - A heredoc or nowdoc assigned to a sensitive key, or passed to a
     *   sensitive call, loses every body line up to its closing marker. Its
     *   opener and closer stay, and so does each line's indentation.
     * - A string literal redacted for a sensitive key that is still open at
     *   the end of its line goes on being redacted on the lines after it, up
     *   to its closing quote, and the value goes on as code after it.
     * - A private key. See {@see redactPrivateKeyBodies()}.
     * - A subclass of `PDO` or `mysqli`. When the lines declare one, its
     *   `parent::__construct(` is read as a credential call in every line.
     *
     * @param  list<string>  $lines  Without their line breaks.
     * @return list<string> One line per line given, in the same order.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    public function redactSource(array $lines): array
    {
        $lines = array_values($lines);
        $this->readsCredentialSubclass = $this->declaresCredentialSubclass($lines);

        try {
            $lines = $this->redactHeredocBodies($this->redactPrivateKeyBodies($lines));
            $scrubbed = [];
            $carried = null;

            foreach ($lines as $line) {
                if ($line === '') {
                    $scrubbed[] = $line;
                    $carried = in_array($carried['kind'] ?? null, [self::CARRIED_VALUE, self::CARRIED_FALLBACK], true) ? null : $carried;

                    continue;
                }

                [$scrubbed[], $open] = $this->scrubText($line, readsCode: true, carried: $carried);
                $carried = $open ?? $this->valueCarriedOver($line);
            }

            return $scrubbed;
        } finally {
            $this->readsCredentialSubclass = false;
        }
    }

    /**
     * Whether the lines declare a class that extends `PDO` or `mysqli`, the
     * global class itself and not one whose name merely starts the same. The
     * lines are read as one text, so the class name can sit on a line after
     * `extends`, with blank lines between; a comment between is not skipped.
     *
     * @param  list<string>  $lines
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function declaresCredentialSubclass(array $lines): bool
    {
        $found = preg_match('/(?<![\w$])extends\s++\\\\?+(?:pdo|mysqli)(?![\w\\\\])/i', implode("\n", $lines));

        if ($found === false) {
            throw new UnexpectedValueException(preg_last_error_msg());
        }

        return $found === 1;
    }

    /**
     * {@see redactString()} and {@see redactSource()} for one string or line.
     * $readsCode says $text is source, where an unquoted value can be
     * code; see {@see redactValue()}. $carried is what the line before left
     * open: its `kind` is one of the `CARRIED_*` constants, `depth` the
     * brackets open inside it and `quote` the quote of a literal it left
     * open, or {@see CARRIED_BLOCK_COMMENT} for a block comment it left open,
     * which is read as a comment up to its end before the value goes on.
     * Comes back with what $text leaves open in turn, or null.
     *
     * Offsets here are byte offsets, as PCRE reports them, hence `8bit` on
     * every length and substring. Every boundary the scrubber cuts at is an
     * ASCII character, so a multibyte character is never split.
     *
     * @param  CarriedState|null  $carried
     * @return array{0: string, 1: CarriedState|null}
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function scrubText(string $text, bool $readsCode, ?array $carried = null): array
    {
        $length = mb_strlen($text, '8bit');
        $scrubbed = '';
        $offset = 0;
        $open = null;

        if ($carried !== null) {
            $start = strspn($text, " \t");
            $scrubbed = mb_substr($text, 0, $start, '8bit');
            $offset = $start;

            if ($carried['quote'] === self::CARRIED_BLOCK_COMMENT) {
                [$commentEnd, $closed] = $this->blockCommentEnd($text, $start);
                $scrubbed .= $this->scrubComment(mb_substr($text, $start, $commentEnd - $start, '8bit'));

                if (! $closed) {
                    return [$scrubbed.mb_substr($text, $commentEnd, null, '8bit'), $carried];
                }

                $offset = $commentEnd;
                $carried['quote'] = null;
            } elseif ($carried['quote'] !== null) {
                [$bodyEnd, $closed] = $this->literalBodyEnd($text, $start, $carried['quote']);
                $scrubbed .= $bodyEnd > $start ? SecretScrubber::REDACTION : '';

                if (! $closed) {
                    return [$scrubbed.mb_substr($text, $bodyEnd, null, '8bit'), $carried];
                }

                $scrubbed .= $carried['quote'];
                $offset = $bodyEnd + 1;
            }

            $fallback = $carried['kind'] === self::CARRIED_FALLBACK
                ? $this->matchAt('/\G(?:\?\?=?+|\?:)[ \t]*+/', $text, $offset)
                : '';
            $scrubbed .= $fallback;
            $offset += mb_strlen($fallback, '8bit');

            $value = match ($carried['kind']) {
                self::CARRIED_VALUE => $this->redactValue($text, $offset, true),
                self::CARRIED_FALLBACK => $fallback === '' ? null : $this->redactValue($text, $offset, true),
                self::CARRIED_CALL => $this->redactCallValue($text, $offset, $readsCode, $carried['depth']),
                default => $this->redactCodeValue($text, $offset, false, $carried['depth']),
            };

            if ($value !== null) {
                $scrubbed .= $value[0];
                [, $offset, $open] = $value;
            }
        }

        while ($offset < $length) {
            $found = preg_match($this->anchorPattern(), $text, $matches, PREG_OFFSET_CAPTURE | PREG_UNMATCHED_AS_NULL, $offset);

            if ($found === false) {
                throw new UnexpectedValueException(preg_last_error_msg());
            }

            if ($found === 0) {
                break;
            }

            $anchorEnd = $matches[0][1] + mb_strlen((string) $matches[0][0], '8bit');
            $value = match (true) {
                ($matches['call'][1] ?? -1) >= 0 => $this->redactCallValue($text, $anchorEnd, $readsCode),
                ($matches['comma'][1] ?? -1) >= 0 => $this->redactQuotedValue($text, $anchorEnd),
                default => $this->redactValue($text, $anchorEnd, $readsCode),
            };

            $scrubbed .= mb_substr($text, $offset, $anchorEnd - $offset, '8bit');
            $offset = $anchorEnd;

            if ($value !== null) {
                [$replacement, $offset, $open] = $value;
                $scrubbed .= $replacement;
            }
        }

        return [$scrubbed.mb_substr($text, $offset, null, '8bit'), $open];
    }

    /**
     * The pattern that finds where a secret value starts: a sensitive key and
     * the separator after it.
     *
     * - A key is a token of `[\w.\-]` holding a sensitive fragment, optionally
     *   quoted and optionally closing a subscript: `password=`, `"api_key":`,
     *   `'token' =>`, `$config['db']['password'] =`. A quoted key that closes
     *   a call is one too, but only before a fallback:
     *   `$request->input('password') ?? 'default'`. Before a comparison it is
     *   not, since `strpos($x, 'token') !== false` is everywhere.
     * - The separator is `=>`, `:`, `=`, `.=`, `??=`, a comparison (`==`,
     *   `===`, `!=`, `!==`) or a fallback (`??`, `?:`), held atomically so
     *   `=>` can never be taken as `=` followed by a value of `>`, nor `??=` as
     *   `??`. `::` is not a separator, so `PersonalAccessToken::findToken()`
     *   stays readable, and neither is the `?` of a full ternary.
     * - A quoted key followed by `,` and a quote is an anchor too:
     *   `define('STRIPE_SECRET', '...')`, `env('API_KEY', '...')`. Its value is
     *   read as a quoted value only.
     * - A call to a function or method whose name holds a sensitive fragment
     *   is an anchor as well, up to its `(`: `Stripe::setApiKey(`,
     *   `$client->setToken(`, `Http::withToken(`. What follows is read as a code
     *   value inside the call's parentheses, so its literals are redacted, every
     *   argument of it, and a call with no literal stays as written. So is a
     *   call on {@see CREDENTIAL_CALLS}, matched by its whole name and allowed
     *   whitespace before its `(`: `new PDO(`, `mysqli_connect (`. A credential
     *   passed by position to any other call is not recognised. A name that
     *   ends in `Exception` or `Error` is not a sensitive call: its argument
     *   is a message, which the error carries as its message anyway, so
     *   `throw new TokenMismatchException('CSRF token mismatch.')` stays
     *   readable.
     *
     * Three details are load-bearing, all of them about cost. It runs on stack
     * traces and log messages, which are the longest, least structured strings
     * the SDK ever touches, and the naive spelling
     * `[\w.\-]*(?:fragment)[\w.\-]*` is quadratic on a long word-character run:
     * every start position re-tries every prefix length. On a 50k run that is
     * billions of steps, which PCRE ends by hitting its backtrack limit.
     *
     * - `(?<![\w.\-])` means a match can only START where a key token can, so a
     *   long word run is entered once instead of once per character. This is
     *   what turns the scan linear.
     * - The prefix is bounded to {@see MAX_KEY_PREFIX} characters. It exists to
     *   keep the full key name in the anchor, and no real key name (`stripe_`,
     *   `user_api_`) comes close. A sensitive fragment buried further than that
     *   into one unbroken token is not recognised, which is the one case this
     *   spelling gives up on deliberately.
     * - Every other repeat is possessive. The characters that can follow a key
     *   are all outside `[\w.\-]`, so giving characters back can never help it
     *   match: the backtracking it would do is pure waste.
     */
    private function anchorPattern(): string
    {
        $variant = (int) $this->readsCredentialSubclass;

        if (isset($this->anchorPatterns[$variant])) {
            return $this->anchorPatterns[$variant];
        }

        [$key, $call] = $this->keyAndCallPatterns();
        $separator = '(?>=>|:(?!:)|!==?|===?|\.=|\?\?=|\?\?|\?:|=)';

        return $this->anchorPatterns[$variant] = '/(?<![\w.\-])(?:'
            .'["\']?'.$key.$this->keyClose().'\s*+'.$separator.'\s*+'
            .'|(?<comma>["\']'.$key.'["\']'.$this->messageKeyGuard().'\s*+,\s*+)(?=["\'])'
            .')|(?<!\w)(?<call>'.$call.')/i';
    }

    /**
     * The sub-patterns for a sensitive key and for the name of a sensitive
     * call up to its `(`, as {@see anchorPattern()} describes them.
     *
     * @return array{0: string, 1: string}
     */
    private function keyAndCallPatterns(): array
    {
        $alternation = implode('|', array_map(
            static fn (string $fragment): string => preg_quote($fragment, '/'),
            $this->fragments
        ));

        return [
            '[\w.\-]{0,'.self::MAX_KEY_PREFIX.'}(?:'.$alternation.')[\w.\-]*+',
            '(?:\w{0,'.self::MAX_KEY_PREFIX.'}(?:'.$alternation.')\w*+(?<!exception|error)'
                .'|(?:'.implode('|', $this->credentialCalls()).')\s*+)\(',
        ];
    }

    /**
     * What may follow a key in {@see anchorPattern()} and {@see carryPatterns()}
     * before its separator: its closing quote, unless it names a validation
     * message, then the `]` of a subscript or, before a fallback only, the `)`
     * of a call it is the argument of, after any spaces or tabs. Where the
     * fallback is on the next line, $fallbackFollows is false and the `)` is
     * taken without looking for it.
     */
    private function keyClose(bool $fallbackFollows = true): string
    {
        return '["\']?'.$this->messageKeyGuard()
            .'(?:\]|(?<=["\'])[ \t]*+\)'.($fallbackFollows ? '(?=\s*+\?[?:])' : '').')?';
    }

    /**
     * A lookbehind, placed just past a key's closing quote, that refuses a
     * quoted key whose last dot segment is a {@see VALIDATION_RULES} entry.
     * Its alternatives are fixed-length words, so it costs a constant per key.
     */
    private function messageKeyGuard(): string
    {
        return '(?<!\.(?:'.implode('|', self::VALIDATION_RULES).')["\'])';
    }

    /**
     * {@see CREDENTIAL_CALLS}, plus {@see PARENT_CONSTRUCTOR_CALL} while the
     * lines being read declare a subclass of `PDO` or `mysqli`.
     *
     * @return list<string>
     */
    private function credentialCalls(): array
    {
        return $this->readsCredentialSubclass
            ? [...self::CREDENTIAL_CALLS, self::PARENT_CONSTRUCTOR_CALL]
            : self::CREDENTIAL_CALLS;
    }

    /**
     * The redacted form of the value that starts at $offset, the offset just
     * past it and what it leaves open at the end of the line (see
     * {@see scrubText()}), or null when nothing there is a value.
     *
     * Only in source ($readsCode) is an unquoted value read as code, keeping
     * its code and losing its literals. In a message, a trace or a command
     * line, `password=$Up3r`, `Bearer $TOKEN` and `token=(abc)` are not code:
     * the shell or the developer already put the secret there. So outside
     * source an unquoted value is redacted whole, see {@see proseValueEnd()}.
     *
     * @return array{0: string, 1: int, 2: CarriedState|null}|null
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function redactValue(string $text, int $offset, bool $readsCode): ?array
    {
        $scheme = $this->matchAt('/\G(?:bearer|basic|digest)\s++(?![,;&)\]}]|$)/i', $text, $offset);
        $start = $offset + mb_strlen($scheme, '8bit');
        $first = $text[$start] ?? '';

        if ($first === '') {
            return null;
        }

        if ($first === '"' || $first === "'") {
            $quoted = $this->redactQuotedValue($text, $start);

            return $quoted === null ? null : [$scheme.$quoted[0], $quoted[1], $quoted[2]];
        }

        if (! $readsCode) {
            $end = $this->proseValueEnd($text, $start);

            return $end === $start ? null : [$scheme.SecretScrubber::REDACTION, $end, null];
        }

        $heredoc = $this->matchAt('/\G<<<[ \t]*+(["\']?)[A-Za-z_]\w*+\1/', $text, $start);

        if ($heredoc !== '') {
            return [$scheme.$heredoc, $start + mb_strlen($heredoc, '8bit'), null];
        }

        if ($this->startsCodeValue($text, $start)) {
            [$code, $end, $open] = $this->redactCodeValue($text, $start, false);

            return [$scheme.$code, $end, $open];
        }

        $spacedName = $this->spacedCallName($text, $start);

        if ($spacedName !== '') {
            [$code, $end, $open] = $this->redactCodeValue($text, $start + mb_strlen($spacedName, '8bit'), false);

            return [$scheme.SecretScrubber::REDACTION.$code, $end, $open];
        }

        return $this->redactBareValue($text, $start, $scheme);
    }

    /**
     * A bare token at $offset redacted whole behind $scheme, or null when
     * there is none.
     *
     * @return array{0: string, 1: int, 2: null}|null
     */
    private function redactBareValue(string $text, int $offset, string $scheme): ?array
    {
        $bareLength = strcspn($text, self::BARE_VALUE_STOPS, $offset);

        if ($bareLength === 0) {
            return null;
        }

        return [$scheme.SecretScrubber::REDACTION, $offset + $bareLength, null];
    }

    /**
     * Where an unquoted value outside source that starts at $offset ends: at a
     * bare value's stop, except that a bracket it reaches is followed to its
     * matching close first. So `Hash::make('x')`, `foo(bar, 'baz')` and
     * `(abc)` are redacted whole, and no literal inside one is left behind
     * the placeholder. A `new` before a constructor call is part of the value,
     * so `new Foo('x')` loses `'x'` too.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function proseValueEnd(string $text, int $offset): int
    {
        $position = $offset + mb_strlen($this->matchAt('/\Gnew\s++(?=\\\\?+[A-Za-z_][\w\\\\]*+\()/i', $text, $offset), '8bit');

        while (true) {
            $position += strcspn($text, self::BARE_VALUE_STOPS.'([{', $position);

            if (! in_array($text[$position] ?? '', ['(', '[', '{'], true)) {
                return $position;
            }

            $position = $this->bracketedValueEnd($text, $position);
        }
    }

    /**
     * The offset just past the bracket that closes the one opened at $offset,
     * counting `()[]{}` alike and skipping string literals, or the end of the
     * line when nothing closes it.
     */
    private function bracketedValueEnd(string $text, int $offset): int
    {
        $length = mb_strlen($text, '8bit');
        $depth = 0;
        $position = $offset;

        while (true) {
            $position += strcspn($text, "\"'()[]{}\r\n", $position);

            if ($position >= $length) {
                return $length;
            }

            $character = $text[$position];

            if ($character === "\r" || $character === "\n") {
                return $position;
            }

            if ($character === '"' || $character === "'") {
                [$bodyEnd, $closed] = $this->quotedBodyEnd($text, $position);

                if (! $closed) {
                    return $bodyEnd;
                }

                $position = $bodyEnd + 1;

                continue;
            }

            $depth += str_contains('([{', $character) ? 1 : -1;
            $position++;

            if ($depth === 0) {
                return $position;
            }
        }
    }

    /**
     * Whether a code value starts at $offset: a variable, an opening bracket,
     * an attribute, `new`, `clone`, `fn`, `function`, `static` or `match`, or a name
     * (namespaced with `\` or chained with `.`) directly followed by `(`, `::`,
     * `->` or `?->`, optionally behind one `@` or `!`.
     *
     * A `$` counts only before a character a variable name can start with, so
     * a bcrypt hash such as `$2y$10$...` stays a bare token and is redacted.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function startsCodeValue(string $text, int $offset): bool
    {
        $name = '[A-Za-z_\x80-\xff][\w\x80-\xff]*+';

        return $this->matchAt(
            '/\G[@!]?+(?:\$[A-Za-z_\x80-\xff{$]|[\[({]|#\[|(?:new|clone|fn|function|static|match)(?=[\s(])'
            .'|\\\\?'.$name.'(?:[\\\\.]'.$name.')*+(?:\(|::|\??->))/i',
            $text,
            $offset,
        ) !== '';
    }

    /**
     * The name at $offset when spaces or tabs, and then what
     * {@see startsCodeValue()} looks for after a name, follow it, or `''`. PHP
     * allows `bcrypt ('x')`, but a word spaced from a bracket or an arrow is as
     * likely the secret in a comment (`password: hunter2 (old)`). So the name
     * is redacted as a bare token would be, and only what follows is read as
     * code, which keeps its literals from shipping either way.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function spacedCallName(string $text, int $offset): string
    {
        $name = '[A-Za-z_\x80-\xff][\w\x80-\xff]*+';

        return $this->matchAt(
            '/\G[@!]?+\\\\?'.$name.'(?:[\\\\.]'.$name.')*+(?=[ \t]++(?:\(|::|\??->))/',
            $text,
            $offset,
        );
    }

    /**
     * The arguments of a sensitive call that start at $offset, read as
     * {@see redactCodeValue()} reads them, and then its fallback: a call whose
     * name says it returns a secret, `$user->getToken() ?? 'x'`, falls back to
     * one. So when `??` or `?:` follows the call's closing `)`, the value after
     * it is read as the call's value, and when nothing but blanks follows it,
     * a fallback that starts the next line is. Anything else after it, a
     * comparison or a chained `->value`, leaves it a plain call.
     *
     * The call's own arguments are balanced by the one pass that reads them,
     * so nothing here has to match an argument list.
     *
     * @return array{0: string, 1: int, 2: CarriedState|null}
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function redactCallValue(string $text, int $offset, bool $readsCode, int $depth = 0): array
    {
        [$code, $end, $open] = $this->redactCodeValue($text, $offset, true, $depth);

        if ($open !== null || ($text[$end] ?? '') !== ')') {
            return [$code, $end, $open];
        }

        $fallback = $this->matchAt('/\G\)[ \t]*+(?:\?\?(?!=)|\?:)[ \t]*+/', $text, $end);

        if ($fallback !== '') {
            $after = $end + mb_strlen($fallback, '8bit');
            $value = $this->redactValue($text, $after, $readsCode);

            return $value === null ? [$code.$fallback, $after, null] : [$code.$fallback.$value[0], $value[1], $value[2]];
        }

        $lineEnd = $this->matchAt('/\G\)[ \t]*+$/', $text, $end);

        return $lineEnd === ''
            ? [$code, $end, null]
            : [$code.$lineEnd, $end + mb_strlen($lineEnd, '8bit'), ['kind' => self::CARRIED_FALLBACK, 'depth' => 0, 'quote' => null]];
    }

    /**
     * A code value with the body of every string literal in it redacted, the
     * offset just past it, and what it leaves open when it runs to the end of
     * the line with a bracket or a literal still open. $depth is the brackets
     * already open where it starts, when it goes on from a line before.
     *
     * The value ends at the end of its line, at a closing bracket that has no
     * opening one inside the value (for a call, the one that closes it), at a
     * `,` (not inside a call, where it only separates arguments) or `;` outside
     * every bracket, or where a `?>` starts. A `//`, `/*` or `#` comment ends
     * it too, unless the value is inside a call or a bracket: there the comment
     * is scrubbed as prose and passed over, so a block comment between two
     * arguments costs nothing and a comment that runs to the end of the line
     * leaves the value open for the next one. A literal runs as a quoted value
     * does, so a comma, bracket or comment marker inside one is never taken for
     * the end. This is one pass over the value: each step jumps to the next
     * character that can matter.
     *
     * @return array{0: string, 1: int, 2: CarriedState|null}
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function redactCodeValue(string $text, int $offset, bool $insideCall, int $depth = 0): array
    {
        $length = mb_strlen($text, '8bit');
        $redacted = '';
        $kept = $offset;
        $position = $offset;
        $openQuote = null;
        $reachedLineEnd = false;

        while (true) {
            $position += strcspn($text, "\"'()[]{},;/#?\r\n", $position);

            if ($position >= $length) {
                $reachedLineEnd = true;

                break;
            }

            $character = $text[$position];
            $next = $text[$position + 1] ?? '';

            if ($character === '"' || $character === "'") {
                [$bodyEnd, $closed] = $this->quotedBodyEnd($text, $position);

                if ($bodyEnd > $position + 1
                    && ! $this->opensHeredoc($text, $position)
                    && ! ($closed && $this->namesLookup($text, $position, $bodyEnd))) {
                    $redacted .= mb_substr($text, $kept, $position + 1 - $kept, '8bit').SecretScrubber::REDACTION;
                    $kept = $bodyEnd;
                }

                $position = $closed ? $bodyEnd + 1 : $bodyEnd;
                $openQuote = $closed ? null : $character;

                continue;
            }

            if ($character === "\r" || $character === "\n") {
                $reachedLineEnd = true;

                break;
            }

            if ($character === '(' || $character === '[' || $character === '{') {
                $depth++;
            } elseif ($character === ')' || $character === ']' || $character === '}') {
                if ($depth === 0) {
                    break;
                }

                $depth--;
            } elseif ($depth === 0 && ($character === ';' || ($character === ',' && ! $insideCall))) {
                break;
            } elseif ($character === '?' && $next === '>') {
                break;
            } elseif (($character === '/' && ($next === '/' || $next === '*')) || ($character === '#' && $next !== '[')) {
                if ($this->scrubbingComment || (! $insideCall && $depth === 0)) {
                    break;
                }

                [$commentEnd, $closed] = $this->commentEnd($text, $position);
                $redacted .= mb_substr($text, $kept, $position - $kept, '8bit')
                    .$this->scrubComment(mb_substr($text, $position, $commentEnd - $position, '8bit'));
                $kept = $position = $commentEnd;

                if (! $closed) {
                    $reachedLineEnd = true;
                    $openQuote = $character === '/' && $next === '*' ? self::CARRIED_BLOCK_COMMENT : null;

                    break;
                }

                continue;
            }

            $position++;
        }

        $open = $reachedLineEnd && ($insideCall || $depth > 0 || $openQuote !== null)
            ? ['kind' => $insideCall ? self::CARRIED_CALL : self::CARRIED_CODE, 'depth' => $depth, 'quote' => $openQuote]
            : null;

        return [$redacted.mb_substr($text, $kept, $position - $kept, '8bit'), $position, $open];
    }

    /**
     * Where the comment that starts at $offset ends, and whether it closes
     * before the end of its line: a block comment just past its closing
     * marker, a line comment at the end of its line.
     *
     * @return array{0: int, 1: bool}
     */
    private function commentEnd(string $text, int $offset): array
    {
        if ($text[$offset] !== '/' || $text[$offset + 1] !== '*') {
            return [$offset + strcspn($text, "\r\n", $offset), false];
        }

        return $this->blockCommentEnd($text, $offset + 2);
    }

    /**
     * Where a block comment that is open at $from ends, just past its closing
     * marker, and whether that marker comes before the end of the line.
     *
     * @return array{0: int, 1: bool}
     */
    private function blockCommentEnd(string $text, int $from): array
    {
        $position = $from;

        while (true) {
            $position += strcspn($text, "*\r\n", $position);

            if (($text[$position] ?? '') !== '*') {
                return [$position, false];
            }

            if (($text[$position + 1] ?? '') === '/') {
                return [$position + 2, true];
            }

            $position++;
        }
    }

    /**
     * A comment inside a code value, scrubbed as prose.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function scrubComment(string $comment): string
    {
        $this->scrubbingComment = true;

        try {
            return $this->scrubText($comment, readsCode: false)[0];
        } finally {
            $this->scrubbingComment = false;
        }
    }

    /**
     * Whether the closed string literal from the quote at $open to the one at
     * $close is a name looked up rather than a value: the first argument of a
     * global `env()`, `getenv()` or `config()` call, or the subscript of
     * `$_ENV` or `$_SERVER`, alone in its slot. `env('DB_PASSWORD', 'x')` names
     * the secret and holds it only in its default. A method or a namespaced
     * function of the same name is not the lookup, and a literal joined onto
     * something else is not a plain name, so both stay redacted.
     */
    private function namesLookup(string $text, int $open, int $close): bool
    {
        $bracketEnd = $this->blanksBefore($text, $open);
        $bracket = $bracketEnd > 0 ? $text[$bracketEnd - 1] : '';
        $after = $close + 1 + strspn($text, " \t", $close + 1);
        $closer = $text[$after] ?? '';
        $nameEnd = $this->blanksBefore($text, $bracketEnd - 1);

        if ($bracket === '[') {
            return $closer === ']' && array_any(
                self::LOOKUP_SUPERGLOBALS,
                fn (string $variable): bool => $this->endsWithAt($text, $nameEnd, $variable, caseInsensitive: false),
            );
        }

        if ($bracket !== '(' || ($closer !== ',' && $closer !== ')')) {
            return false;
        }

        foreach (self::LOOKUP_FUNCTIONS as $function) {
            if (! $this->endsWithAt($text, $nameEnd, $function, caseInsensitive: true)) {
                continue;
            }

            $start = $nameEnd - mb_strlen($function, '8bit');
            if ($start > 0 && $text[$start - 1] === '\\') {
                $start--;
            }

            return $start === 0 || strpbrk($text[$start - 1], self::NAME_CHARACTERS.'$\\>:') === false;
        }

        return false;
    }

    /**
     * The offset where the run of spaces and tabs that ends at $offset starts.
     */
    private function blanksBefore(string $text, int $offset): int
    {
        while ($offset > 0 && ($text[$offset - 1] === ' ' || $text[$offset - 1] === "\t")) {
            $offset--;
        }

        return $offset;
    }

    /**
     * Whether $text holds $needle ending just before $end.
     */
    private function endsWithAt(string $text, int $end, string $needle, bool $caseInsensitive): bool
    {
        $length = mb_strlen($needle, '8bit');

        return $end >= $length && substr_compare($text, $needle, $end - $length, $length, $caseInsensitive) === 0;
    }

    /**
     * Whether the quote at $offset names the marker of a heredoc or nowdoc
     * (`<<<"EOT"`, `<<<'EOT'`) rather than opening a string literal.
     */
    private function opensHeredoc(string $text, int $offset): bool
    {
        $from = max(0, $offset - 16);

        return str_ends_with(mb_rtrim(mb_substr($text, $from, $offset - $from, '8bit'), " \t"), '<<<');
    }

    /**
     * A quoted value that starts at $offset, redacted whole with its quotes
     * kept, the offset just past it and what it leaves open when it runs to
     * the end of the line unclosed, or null when its body is empty.
     *
     * A literal concatenated onto it (`'abc' . 'def'`, `'abc' . $x . 'def'`)
     * is part of the same secret, so from a `.` followed by a quote or a `$`
     * on, the value is read on as a code value. A `.` followed by anything
     * else is more likely a full stop in prose.
     *
     * @return array{0: string, 1: int, 2: CarriedState|null}|null
     */
    private function redactQuotedValue(string $text, int $offset): ?array
    {
        [$bodyEnd, $closed] = $this->quotedBodyEnd($text, $offset);

        if ($bodyEnd === $offset + 1) {
            return null;
        }

        $quote = $text[$offset];

        if (! $closed) {
            return [$quote.SecretScrubber::REDACTION, $bodyEnd, ['kind' => self::CARRIED_CODE, 'depth' => 0, 'quote' => $quote]];
        }

        $after = $bodyEnd + 1;
        $dot = $after + strspn($text, " \t", $after);
        $next = $dot + 1 + strspn($text, " \t", $dot + 1);

        if (($text[$dot] ?? '') === '.' && in_array($text[$next] ?? '', ['"', "'", '$'], true)) {
            [$code, $end, $open] = $this->redactCodeValue($text, $after, false);

            return [$quote.SecretScrubber::REDACTION.$quote.$code, $end, $open];
        }

        return [$quote.SecretScrubber::REDACTION.$quote, $after, null];
    }

    /**
     * Where the body of the string literal opened at $offset ends, and whether
     * a closing quote ends it.
     *
     * @return array{0: int, 1: bool}
     */
    private function quotedBodyEnd(string $text, int $offset): array
    {
        return $this->literalBodyEnd($text, $offset + 1, $text[$offset]);
    }

    /**
     * Where the body of a $quote literal that is open at $from ends, and
     * whether a closing quote ends it. A backslash escapes the character after
     * it; the body ends unclosed at a line break or the end of the string.
     *
     * @return array{0: int, 1: bool}
     */
    private function literalBodyEnd(string $text, int $from, string $quote): array
    {
        $length = mb_strlen($text, '8bit');
        $position = $from;

        while (true) {
            $position += strcspn($text, $quote."\\\r\n", $position);

            if ($position >= $length) {
                return [$length, false];
            }

            $character = $text[$position];

            if ($character === $quote) {
                return [$position, true];
            }

            $escaped = $text[$position + 1] ?? '';

            if ($character !== '\\' || $escaped === '' || $escaped === "\r" || $escaped === "\n") {
                return [$position, false];
            }

            $position += 2;
        }
    }

    /**
     * The value of a sensitive key that $line ends in after `=>`, `=`, `.=`,
     * `??=` or a fallback (`??`, `?:`), left for the start of the next line,
     * or else the fallback of a sensitive read $line ends in (a variable, a
     * subscript or a call's quoted argument), or null.
     *
     * @return CarriedState|null
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function valueCarriedOver(string $line): ?array
    {
        foreach ([self::CARRIED_VALUE, self::CARRIED_FALLBACK] as $kind) {
            $found = preg_match($this->carryPatterns()[$kind], $line);

            if ($found === false) {
                throw new UnexpectedValueException(preg_last_error_msg());
            }

            if ($found === 1) {
                return ['kind' => $kind, 'depth' => 0, 'quote' => null];
            }
        }

        return null;
    }

    /**
     * The patterns {@see valueCarriedOver()} and {@see redactHeredocBodies()}
     * look for at the end of a line: a sensitive key and an assignment
     * followed by nothing, a sensitive key read followed by nothing, or an
     * assignment or a sensitive call's `(` followed by a heredoc opener.
     *
     * @return array{value: string, fallback: string, heredoc: string}
     */
    private function carryPatterns(): array
    {
        $variant = (int) $this->readsCredentialSubclass;

        if (isset($this->carryPatterns[$variant])) {
            return $this->carryPatterns[$variant];
        }

        [$key, $call] = $this->keyAndCallPatterns();
        $assignment = '(?<![\w.\-])["\']?'.$key.$this->keyClose().'\s*+(?:=>|\?\?=|\?\?|\?:|\.=|=)';

        return $this->carryPatterns[$variant] = [
            'value' => '/'.$assignment.'\s*+$/i',
            'fallback' => '/(?<![\w.\-])["\']?'.$key.$this->keyClose(fallbackFollows: false).'\s*+$/i',
            'heredoc' => '/(?:'.$assignment.'|(?<!\w)'.$call.')'
                .'\s*+<<<[ \t]*+(?<quote>["\']?)(?<marker>[A-Za-z_]\w*+)\k<quote>\s*+$/i',
        ];
    }

    /**
     * Replace the body lines of every heredoc or nowdoc that holds a sensitive
     * value, see {@see redactSource()}. A body runs to the line its closing
     * marker starts, or to the end of the window. Besides the openers of
     * {@see carryPatterns()}, a heredoc after `??` or `?:` opens one when what
     * it falls back from is a sensitive read, see {@see fallbackHeredocMarker()}.
     *
     * @param  list<string>  $lines
     * @return list<string>
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function redactHeredocBodies(array $lines): array
    {
        $closing = null;
        $previous = '';

        foreach ($lines as $index => $line) {
            $lineBefore = $previous;
            $previous = $line;

            if ($closing !== null) {
                $indent = strspn($line, " \t");
                $markerLength = mb_strlen($closing, '8bit');

                if (mb_substr($line, $indent, $markerLength, '8bit') === $closing
                    && strspn($line, self::NAME_CHARACTERS, $indent + $markerLength) === 0) {
                    $closing = null;

                    continue;
                }

                if ($indent < mb_strlen($line, '8bit')) {
                    $lines[$index] = mb_substr($line, 0, $indent, '8bit').SecretScrubber::REDACTION;
                }

                continue;
            }

            $found = preg_match($this->carryPatterns()['heredoc'], $line, $matches);

            if ($found === false) {
                throw new UnexpectedValueException(preg_last_error_msg());
            }

            $closing = $found === 1 ? $matches['marker'] : $this->fallbackHeredocMarker($line, $lineBefore);
        }

        return $lines;
    }

    /**
     * The marker of a heredoc or nowdoc that $line opens after `??` or `?:`
     * when what it falls back from is a sensitive read, or null. The read is
     * whatever comes before the separator on $line, or $lineBefore when the
     * separator starts $line. It is recognised as the line pass recognises
     * the read before a fallback on the next line: a sensitive call that the
     * text ends with ({@see redactCallValue()}) or a key the text ends in
     * ({@see valueCarriedOver()}).
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function fallbackHeredocMarker(string $line, string $lineBefore): ?string
    {
        $found = preg_match(
            '/(?:\?\?|\?:)[ \t]*+<<<[ \t]*+(["\']?)(?<marker>[A-Za-z_]\w*+)\1\s*+$/',
            $line,
            $matches,
            PREG_OFFSET_CAPTURE,
        );

        if ($found === false) {
            throw new UnexpectedValueException(preg_last_error_msg());
        }

        if ($found === 0) {
            return null;
        }

        $read = mb_substr($line, 0, $matches[0][1], '8bit');
        $read = mb_trim($read, " \t") === '' ? $lineBefore : $read;

        if ($read === '') {
            return null;
        }

        $endsInSensitiveRead = ($this->scrubText($read, readsCode: true)[1]['kind'] ?? null) === self::CARRIED_FALLBACK
            || ($this->valueCarriedOver($read)['kind'] ?? null) === self::CARRIED_FALLBACK;

        return $endsInSensitiveRead ? $matches['marker'][0] : null;
    }

    /**
     * Replace the body of every private key in a window with the placeholder,
     * leaving its `-----BEGIN ... PRIVATE KEY-----` and `-----END ...-----`
     * markers, each line's indentation and the quotes, `.` and `\n` around the
     * body as they were, so the code still reads as what it is.
     *
     * A window is a cut from the middle of a file, so it can start inside a
     * key: an END marker with no BEGIN before it means everything before it is
     * body. It can also sit wholly inside a long body, with neither marker, so
     * any line that holds nothing but a base64 run of
     * {@see MIN_KEY_BODY_LINE} or more characters, with digits and both cases
     * among them, is redacted as well. Requiring all three keeps a long path
     * or word alone on a line readable, and a real body line has them all.
     * Certificate markers are not private keys, though their body lines can
     * still be caught by that rule.
     *
     * @param  list<string>  $lines
     * @return list<string>
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function redactPrivateKeyBodies(array $lines): array
    {
        $marker = '/-----(?<kind>BEGIN|END) [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/';
        $markers = [];
        $insideKey = null;

        foreach ($lines as $index => $line) {
            if (preg_match_all($marker, $line, $markers[$index], PREG_SET_ORDER | PREG_OFFSET_CAPTURE) === false) {
                throw new UnexpectedValueException(preg_last_error_msg());
            }

            if ($insideKey === null && $markers[$index] !== []) {
                $insideKey = $markers[$index][0]['kind'][0] === 'END';
            }
        }

        $insideKey ??= false;

        foreach ($lines as $index => $line) {
            if ($markers[$index] === []) {
                if ($insideKey || $this->isKeyBodyLine($line)) {
                    $lines[$index] = $this->redactKeyBody($line);
                }

                continue;
            }

            $rebuilt = '';
            $position = 0;

            foreach ($markers[$index] as $found) {
                [$text, $at] = $found[0];
                $before = mb_substr($line, $position, $at - $position, '8bit');
                $rebuilt .= ($insideKey ? $this->redactKeyBody($before) : $before).$text;
                $position = $at + mb_strlen($text, '8bit');
                $insideKey = $found['kind'][0] === 'BEGIN';
            }

            $rest = mb_substr($line, $position, null, '8bit');
            $lines[$index] = $rebuilt.($insideKey ? $this->redactKeyBody($rest) : $rest);
        }

        return $lines;
    }

    /**
     * Whether $line holds nothing but what a private key body line looks like
     * outside its markers, see {@see redactPrivateKeyBodies()}.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function isKeyBodyLine(string $line): bool
    {
        [, $body] = $this->splitKeyBody($line);

        if (mb_strlen($body, '8bit') < self::MIN_KEY_BODY_LINE) {
            return false;
        }

        return $this->matchAt('/\G[A-Za-z0-9+\/]++={0,2}+$/', $body, 0) !== ''
            && strpbrk($body, '0123456789') !== false
            && strpbrk($body, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') !== false
            && strpbrk($body, 'abcdefghijklmnopqrstuvwxyz') !== false;
    }

    /**
     * $segment with its key body replaced by the placeholder, or as it was
     * when it holds no body.
     */
    private function redactKeyBody(string $segment): string
    {
        [$before, $body, $after] = $this->splitKeyBody($segment);

        return $body === '' ? $segment : $before.SecretScrubber::REDACTION.$after;
    }

    /**
     * $segment split into what surrounds a key body and the body itself: the
     * whitespace, quotes, `.` concatenation and `\n` or `\r` escapes before it,
     * and those plus a trailing `,`, `;` or `)` after it.
     *
     * @return array{0: string, 1: string, 2: string}
     */
    private function splitKeyBody(string $segment): array
    {
        $length = mb_strlen($segment, '8bit');
        $start = 0;

        while ($start < $length) {
            if (str_contains(" \t.\"'", $segment[$start])) {
                $start++;
            } elseif ($segment[$start] === '\\' && in_array($segment[$start + 1] ?? '', ['n', 'r'], true)) {
                $start += 2;
            } else {
                break;
            }
        }

        $end = $length;

        while ($end > $start) {
            if (str_contains(" \t.\"',;)", $segment[$end - 1])) {
                $end--;
            } elseif ($end - 2 >= $start && $segment[$end - 2] === '\\' && in_array($segment[$end - 1], ['n', 'r'], true)) {
                $end -= 2;
            } else {
                break;
            }
        }

        return [
            mb_substr($segment, 0, $start, '8bit'),
            mb_substr($segment, $start, $end - $start, '8bit'),
            mb_substr($segment, $end, null, '8bit'),
        ];
    }

    /**
     * What $pattern, anchored with `\G`, matches at $offset, or `''`.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function matchAt(string $pattern, string $text, int $offset): string
    {
        $found = preg_match($pattern, $text, $matches, 0, $offset);

        if ($found === false) {
            throw new UnexpectedValueException(preg_last_error_msg());
        }

        return $found === 1 ? $matches[0] : '';
    }
}
