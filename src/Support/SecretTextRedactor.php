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
 * positional secret argument to any other call. A regex finds each key and its separator (the anchor), and the value
 * after it is read by hand, because a code value has to balance brackets and
 * one pattern cannot do that cheaply. See {@see anchorPattern()} for what an
 * anchor is and why the pattern stays linear.
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
 *   starts one, and {@see redactCodeValue()} where it ends.
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
     */
    private const string CARRIED_VALUE = 'value';

    private const string CARRIED_CALL = 'call';

    private const string CARRIED_CODE = 'code';

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
     * {@see anchorPattern()}, built once per instance.
     */
    private ?string $anchorPattern = null;

    /**
     * {@see carryPatterns()}, built once per instance.
     *
     * @var array{value: string, heredoc: string}|null
     */
    private ?array $carryPatterns = null;

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
     *   `=>`, `=`, `.=` or `??=` has the start of the next line read as that
     *   value. Only one line ahead, and never after `:` or a comparison, so
     *   `case 'token':` followed by `return $x;` stays readable.
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
     *
     * @param  list<string>  $lines  Without their line breaks.
     * @return list<string> One line per line given, in the same order.
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    public function redactSource(array $lines): array
    {
        $lines = $this->redactHeredocBodies($this->redactPrivateKeyBodies(array_values($lines)));
        $scrubbed = [];
        $carried = null;

        foreach ($lines as $line) {
            if ($line === '') {
                $scrubbed[] = $line;
                $carried = ($carried['kind'] ?? null) === self::CARRIED_VALUE ? null : $carried;

                continue;
            }

            [$scrubbed[], $open] = $this->scrubText($line, readsCode: true, carried: $carried);
            $carried = $open ?? $this->valueCarriedOver($line);
        }

        return $scrubbed;
    }

    /**
     * {@see redactString()} and {@see redactSource()} for one string or line.
     * $readsCode says $text is source, where an unquoted value can be
     * code; see {@see redactValue()}. $carried is what the line before left
     * open: its `kind` is one of the `CARRIED_*` constants, `depth` the
     * brackets open inside it and `quote` the quote of a literal it left
     * open. Comes back with what $text leaves open in turn, or null.
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

            if ($carried['quote'] !== null) {
                [$bodyEnd, $closed] = $this->literalBodyEnd($text, $start, $carried['quote']);
                $scrubbed .= $bodyEnd > $start ? SecretScrubber::REDACTION : '';

                if (! $closed) {
                    return [$scrubbed.mb_substr($text, $bodyEnd, null, '8bit'), $carried];
                }

                $scrubbed .= $carried['quote'];
                $offset = $bodyEnd + 1;
            }

            $value = $carried['kind'] === self::CARRIED_VALUE
                ? $this->redactValue($text, $offset, true)
                : $this->redactCodeValue($text, $offset, $carried['kind'] === self::CARRIED_CALL, $carried['depth']);

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
                ($matches['call'][1] ?? -1) >= 0 => $this->redactCodeValue($text, $anchorEnd, true),
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
     *   `'token' =>`, `$config['db']['password'] =`.
     * - The separator is `=>`, `:`, `=`, `.=`, `??=` or a comparison (`==`,
     *   `===`, `!=`, `!==`), held atomically so `=>` can never be taken as `=`
     *   followed by a value of `>`. `::` is not a separator, so
     *   `PersonalAccessToken::findToken()` stays readable.
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
     *   passed by position to any other call is not recognised.
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
        if ($this->anchorPattern !== null) {
            return $this->anchorPattern;
        }

        [$key, $call] = $this->keyAndCallPatterns();
        $separator = '(?>=>|:(?!:)|!==?|===?|\.=|\?\?=|=)';

        return $this->anchorPattern = '/(?<![\w.\-])(?:'
            .'["\']?'.$key.'["\']?\]?\s*+'.$separator.'\s*+'
            .'|(?<comma>["\']'.$key.'["\']\s*+,\s*+)(?=["\'])'
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
            '(?:\w{0,'.self::MAX_KEY_PREFIX.'}(?:'.$alternation.')\w*+'
                .'|(?:'.implode('|', self::CREDENTIAL_CALLS).')\s*+)\(',
        ];
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
     * the placeholder.
     */
    private function proseValueEnd(string $text, int $offset): int
    {
        $position = $offset;

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
     * A code value with the body of every string literal in it redacted, the
     * offset just past it, and what it leaves open when it runs to the end of
     * the line with a bracket or a literal still open. $depth is the brackets
     * already open where it starts, when it goes on from a line before.
     *
     * The value ends at the end of its line, at a closing bracket that has no
     * opening one inside the value (for a call, the one that closes it), at a
     * `,` (not inside a call, where it only separates arguments) or `;` outside
     * every bracket, or where a `//`, `/*` or `#` comment or a `?>` starts. A
     * literal runs as a quoted value does, so a comma, bracket or comment
     * marker inside one is never taken for the end. This is one pass over the
     * value: each step jumps to the next character that can matter.
     *
     * @return array{0: string, 1: int, 2: CarriedState|null}
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

                if ($bodyEnd > $position + 1 && ! $this->opensHeredoc($text, $position)) {
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
            } elseif (($character === '/' && ($next === '/' || $next === '*'))
                || ($character === '#' && $next !== '[')
                || ($character === '?' && $next === '>')) {
                break;
            }

            $position++;
        }

        $open = $reachedLineEnd && ($insideCall || $depth > 0 || $openQuote !== null)
            ? ['kind' => $insideCall ? self::CARRIED_CALL : self::CARRIED_CODE, 'depth' => $depth, 'quote' => $openQuote]
            : null;

        return [$redacted.mb_substr($text, $kept, $position - $kept, '8bit'), $position, $open];
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
     * The value of a sensitive key that $line ends in after `=>`, `=`, `.=` or
     * `??=`, left for the start of the next line, or null.
     *
     * @return CarriedState|null
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function valueCarriedOver(string $line): ?array
    {
        $found = preg_match($this->carryPatterns()['value'], $line);

        if ($found === false) {
            throw new UnexpectedValueException(preg_last_error_msg());
        }

        return $found === 1 ? ['kind' => self::CARRIED_VALUE, 'depth' => 0, 'quote' => null] : null;
    }

    /**
     * The patterns {@see valueCarriedOver()} and {@see redactHeredocBodies()}
     * look for at the end of a line: a sensitive key and an assignment
     * followed by nothing, or that or a sensitive call's `(` followed by a
     * heredoc opener.
     *
     * @return array{value: string, heredoc: string}
     */
    private function carryPatterns(): array
    {
        if ($this->carryPatterns !== null) {
            return $this->carryPatterns;
        }

        [$key, $call] = $this->keyAndCallPatterns();
        $assignment = '(?<![\w.\-])["\']?'.$key.'["\']?\]?\s*+(?:=>|=|\.=|\?\?=)';

        return $this->carryPatterns = [
            'value' => '/'.$assignment.'\s*+$/i',
            'heredoc' => '/(?:'.$assignment.'|(?<!\w)'.$call.')'
                .'\s*+<<<[ \t]*+(?<quote>["\']?)(?<marker>[A-Za-z_]\w*+)\k<quote>\s*+$/i',
        ];
    }

    /**
     * Replace the body lines of every heredoc or nowdoc that holds a sensitive
     * value, see {@see redactSource()}. A body runs to the line its closing
     * marker starts, or to the end of the window.
     *
     * @param  list<string>  $lines
     * @return list<string>
     *
     * @throws UnexpectedValueException when PCRE gives up
     */
    private function redactHeredocBodies(array $lines): array
    {
        $closing = null;

        foreach ($lines as $index => $line) {
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

            if ($found === 1) {
                $closing = $matches['marker'];
            }
        }

        return $lines;
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
