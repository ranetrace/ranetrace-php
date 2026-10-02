<?php

declare(strict_types=1);

use Ranetrace\Php\Support\DeviceType;

const IPHONE_SAFARI_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1';

test('it classifies the device a real user agent comes from', function (string $userAgent, DeviceType $deviceType): void {
    expect(DeviceType::fromUserAgent($userAgent))->toBe($deviceType);
})->with([
    'iphone safari' => [IPHONE_SAFARI_UA, DeviceType::Mobile],
    'chrome android phone' => ['Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36', DeviceType::Mobile],
    'samsung phone' => ['Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36', DeviceType::Mobile],
    'firefox android' => ['Mozilla/5.0 (Android 14; Mobile; rv:131.0) Gecko/131.0 Firefox/131.0', DeviceType::Mobile],
    'windows phone' => ['Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 920)', DeviceType::Mobile],
    'blackberry 10' => ['Mozilla/5.0 (BB10; Touch) AppleWebKit/537.10+ (KHTML, like Gecko) Version/10.0.9.2372 Mobile Safari/537.10+', DeviceType::Mobile],
    'opera mini' => ['Opera/9.80 (J2ME/MIDP; Opera Mini/5.1.21214/28.2725; U; ru) Presto/2.8.119 Version/11.10', DeviceType::Mobile],
    'android tablet' => ['Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36', DeviceType::Tablet],
    'kindle fire silk' => ['Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_3; en-us; Silk/1.0.13.81_10003810) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16 Silk-Accelerated=true', DeviceType::Tablet],
    'ipad on ipados 12' => ['Mozilla/5.0 (iPad; CPU OS 12_5_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1', DeviceType::Tablet],
    'windows chrome' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36', DeviceType::Desktop],
    'mac safari' => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15', DeviceType::Desktop],
    'linux firefox' => ['Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0', DeviceType::Desktop],
    'xbox one edge' => ['Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.10586', DeviceType::Console],
    'playstation 5' => ['Mozilla/5.0 (PlayStation; PlayStation 5/2.26) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15', DeviceType::Console],
    'nintendo switch' => ['Mozilla/5.0 (Nintendo Switch; WifiWebAuthApplet) AppleWebKit/606.4 (KHTML, like Gecko) NF/6.0.1.15.4 NintendoBrowser/5.1.0.20393', DeviceType::Console],
]);

test('an ipad on ipados 13 or later is a desktop because it sends a mac user agent', function (): void {
    $ipadOnIpados17 = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15';

    expect(DeviceType::fromUserAgent($ipadOnIpados17))->toBe(DeviceType::Desktop);
});

test('no user agent gives no device type', function (?string $userAgent): void {
    expect(DeviceType::fromUserAgent($userAgent))->toBeNull();
})->with([
    'null' => [null],
    'empty string' => [''],
]);

test('any other string is a user agent and an unrecognised one is a desktop', function (string $userAgent): void {
    expect(DeviceType::fromUserAgent($userAgent))->toBe(DeviceType::Desktop);
})->with([
    'zero' => ['0'],
    'whitespace' => ['   '],
    'curl' => ['curl/8.7.1'],
]);

test('a token inside a longer word is not read as that token', function (string $userAgent): void {
    expect(DeviceType::fromUserAgent($userAgent))->toBe(DeviceType::Desktop);
})->with([
    'silk inside a word' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) Silkworm/2.0 Chrome/140.0.0.0 Safari/537.36'],
    'mobile inside a word' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AutomobileClient/3.1 Chrome/140.0.0.0 Safari/537.36'],
    'mobile at the start of a word' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) MobileIron/1.0 Chrome/140.0.0.0 Safari/537.36'],
    'android inside a word' => ['Mozilla/5.0 (X11; Linux x86_64) Androidish/1.0 Firefox/131.0'],
    'xbox inside a word' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) MyXboxTools/1.0 Chrome/140.0.0.0 Safari/537.36'],
]);

test('a token past the first 1024 characters is not read', function (): void {
    $userAgent = str_repeat('x', DeviceType::MAX_USER_AGENT_LENGTH).' '.IPHONE_SAFARI_UA;

    expect(DeviceType::fromUserAgent($userAgent))->toBe(DeviceType::Desktop);
});

test('the case values are the four device types the backend takes', function (): void {
    expect(array_map(static fn (DeviceType $deviceType): string => $deviceType->value, DeviceType::cases()))
        ->toBe(['mobile', 'tablet', 'desktop', 'console']);
});

test('a console that also sends a tablet token is a console', function (): void {
    $playStationVita = 'Mozilla/5.0 (PlayStation Vita 3.74) AppleWebKit/537.73 (KHTML, like Gecko) Silk/3.2';

    expect(DeviceType::fromUserAgent($playStationVita))->toBe(DeviceType::Console);
});

test('a tablet that also sends mobile is a tablet', function (string $userAgent): void {
    expect(DeviceType::fromUserAgent($userAgent))->toBe(DeviceType::Tablet);
})->with([
    'kindle fire in mobile mode' => ['Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFTT Build/IML74K) AppleWebKit/535.19 (KHTML, like Gecko) Silk/3.4 Mobile Safari/535.19 Silk-Accelerated=true'],
    'firefox on an android tablet' => ['Mozilla/5.0 (Android 14; Tablet; rv:131.0) Gecko/131.0 Firefox/131.0'],
]);

test('opera mini on an android phone is a phone although it sends no mobile token', function (): void {
    $userAgent = 'Opera/9.80 (Android; Opera Mini/36.2.2254/119.132; U; id) Presto/2.12.423 Version/12.16';

    expect(DeviceType::fromUserAgent($userAgent))->toBe(DeviceType::Mobile);
});

test('a model number straight after a token still counts as that token', function (): void {
    $blackBerry9700 = 'BlackBerry9700/5.0.0.862 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/331';

    expect(DeviceType::fromUserAgent($blackBerry9700))->toBe(DeviceType::Mobile);
});

test('a huge user agent is read only up to the cap and never throws', function (): void {
    expect(DeviceType::fromUserAgent(IPHONE_SAFARI_UA.' '.str_repeat('x', 1_000_000)))->toBe(DeviceType::Mobile)
        ->and(DeviceType::fromUserAgent(str_repeat('Androi Mobil Silk ', 100_000)))->toBe(DeviceType::Desktop);
});

test('invalid utf-8 in a user agent does not stop the match', function (): void {
    expect(DeviceType::fromUserAgent("\xff\xfe ".IPHONE_SAFARI_UA))->toBe(DeviceType::Mobile)
        ->and(DeviceType::fromUserAgent(str_repeat("\x80\xff\x00", 700)))->toBeInstanceOf(DeviceType::class);
});
