<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * The browser name and version a user agent string names, or nulls.
 *
 * The rules are checked in order and the first match wins. The order is the
 * point: Edge, Opera and Samsung Internet all carry `Chrome/` and `Safari/`
 * tokens, Chrome carries `Safari/`, so a later rule would claim their UAs.
 *
 * Both values are bounded so a crafted user agent cannot put arbitrary text
 * on the wire: the name is one of six fixed display names, and the version is
 * digits with at most one dot. The version is the major only, except Safari,
 * which keeps major.minor because it ships web-platform features in point
 * releases. A version longer than five digits is not a version and gives null.
 *
 * A crawler is not a browser a visitor used, so a UA that identifies itself as
 * a bot gives nulls even when it also claims Chrome, as Googlebot's does. So
 * does headless Chrome: its token is `HeadlessChrome/`, which the word
 * boundary on each token deliberately does not read as `Chrome/`.
 */
final readonly class BrowserIdentity
{
    /**
     * Only this many characters of the user agent are read. Real ones stay well under it,
     * and no host is required to cap the header before it arrives here.
     */
    public const int MAX_USER_AGENT_LENGTH = 1024;

    private const string BOT_PATTERN = '~(?:bot|crawler|spider)/|compatible; [^;)]*bot~i';

    /**
     * Display name to the pattern that identifies it, in precedence order. The
     * first capture group is the version.
     *
     * @var array<string, array<int, string>>
     */
    private const array RULES = [
        'Edge' => ['~(?<![A-Za-z])(?:Edg|EdgA|EdgiOS|Edge)/(\d{1,5})(?!\d)~'],
        'Opera' => [
            '~(?<![A-Za-z])OPR/(\d{1,5})(?!\d)~',
            '~(?<![A-Za-z])Opera(?![A-Za-z]).*?(?<![A-Za-z])Version/(\d{1,5})(?!\d)~',
            '~(?<![A-Za-z])Opera[/ ](\d{1,5})(?!\d)~',
            '~(?<![A-Za-z])Opera(?![A-Za-z])()~',
        ],
        'Samsung Internet' => ['~(?<![A-Za-z])SamsungBrowser/(\d{1,5})(?!\d)~'],
        'Firefox' => ['~(?<![A-Za-z])(?:Firefox|FxiOS)/(\d{1,5})(?!\d)~'],
        'Chrome' => ['~(?<![A-Za-z])(?:Chrome|CriOS)/(\d{1,5})(?!\d)~'],
        'Safari' => ['~(?<![A-Za-z])Version/(\d{1,5}(?:\.\d{1,5}(?!\d))?)(?!\d).*?(?<![A-Za-z])Safari/~'],
    ];

    public function __construct(
        public ?string $name,
        public ?string $version,
    ) {}

    public static function fromUserAgent(?string $userAgent): self
    {
        if ($userAgent === null || $userAgent === '') {
            return self::unknown();
        }

        $userAgent = mb_substr($userAgent, 0, self::MAX_USER_AGENT_LENGTH);

        if (preg_match(self::BOT_PATTERN, $userAgent) === 1) {
            return self::unknown();
        }

        foreach (self::RULES as $name => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $userAgent, $matches) === 1) {
                    $version = $matches[1];

                    return new self($name, $version === '' ? null : $version);
                }
            }
        }

        return self::unknown();
    }

    public static function unknown(): self
    {
        return new self(null, null);
    }
}
