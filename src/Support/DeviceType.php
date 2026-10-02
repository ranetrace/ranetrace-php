<?php

declare(strict_types=1);

namespace Ranetrace\Php\Support;

/**
 * The kind of device a user agent string comes from. The case values are the
 * strings the backend takes for a visit's `device_type`.
 *
 * Consoles are checked first, because a console browser can also carry a
 * phone token: Edge on the Xbox One sends `Windows Phone`, `Android` and
 * `Mobile Safari` next to `Xbox`. A tablet token beats a phone token, since
 * an iPad and a Kindle in its mobile mode both send `Mobile` too. An Android
 * user agent with no phone token is a tablet: Android phones send `Mobile`
 * and Android tablets leave it out. Phone tokens are checked before that,
 * because Opera Mini on an Android phone names itself instead of sending
 * `Mobile`. Anything no rule claims is a desktop.
 *
 * Tokens are matched case-sensitively, the way devices send them, and never
 * inside a longer word, so `Automobile` is not `Mobile` and `Silkworm` is not
 * Kindle's `Silk/`.
 *
 * An iPad on iPadOS 13 or later is counted as a desktop: its browser sends the
 * same user agent as Safari on a Mac, so nothing in the string tells them apart.
 */
enum DeviceType: string
{
    case Mobile = 'mobile';
    case Tablet = 'tablet';
    case Desktop = 'desktop';
    case Console = 'console';

    /**
     * Only this many characters of the user agent are read, the same cap
     * BrowserIdentity applies to the same header.
     */
    public const int MAX_USER_AGENT_LENGTH = BrowserIdentity::MAX_USER_AGENT_LENGTH;

    private const string CONSOLE_PATTERN = '~(?<![A-Za-z])(?:Nintendo|PlayStation|Xbox)(?![A-Za-z])~';

    private const string TABLET_PATTERN = '~(?<![A-Za-z])(?:iPad|Tablet|PlayBook)(?![A-Za-z])|(?<![A-Za-z])Silk/~';

    private const string PHONE_PATTERN = '~(?<![A-Za-z])(?:Mobile|iPhone|iPod|BlackBerry|BB10|IEMobile|Windows Phone|Opera Mini|Opera Mobi|webOS)(?![A-Za-z])~';

    private const string ANDROID_PATTERN = '~(?<![A-Za-z])Android(?![A-Za-z])~';

    /**
     * The device type the user agent names, or null when there is no user agent.
     * Any other string, even one no rule recognises, is a desktop.
     */
    public static function fromUserAgent(?string $userAgent): ?self
    {
        if ($userAgent === null || $userAgent === '') {
            return null;
        }

        $userAgent = mb_substr($userAgent, 0, self::MAX_USER_AGENT_LENGTH);

        if (preg_match(self::CONSOLE_PATTERN, $userAgent) === 1) {
            return self::Console;
        }

        if (preg_match(self::TABLET_PATTERN, $userAgent) === 1) {
            return self::Tablet;
        }

        if (preg_match(self::PHONE_PATTERN, $userAgent) === 1) {
            return self::Mobile;
        }

        if (preg_match(self::ANDROID_PATTERN, $userAgent) === 1) {
            return self::Tablet;
        }

        return self::Desktop;
    }
}
