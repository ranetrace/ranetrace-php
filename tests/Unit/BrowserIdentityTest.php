<?php

declare(strict_types=1);

use Ranetrace\Php\Support\BrowserIdentity;

const CHROME_DESKTOP_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

test('it names the browser and version a real user agent reports', function (string $userAgent, string $name, string $version): void {
    $browser = BrowserIdentity::fromUserAgent($userAgent);

    expect($browser->name)->toBe($name)
        ->and($browser->version)->toBe($version);
})->with([
    'chrome desktop' => [CHROME_DESKTOP_UA, 'Chrome', '140'],
    'chrome android' => ['Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36', 'Chrome', '140'],
    'chrome on ios' => ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/140.0.7339.101 Mobile/15E148 Safari/604.1', 'Chrome', '140'],
    'edge desktop' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.3485.54', 'Edge', '140'],
    'edge android' => ['Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36 EdgA/140.0.3485.54', 'Edge', '140'],
    'edge on ios' => ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/140.3485.64 Mobile/15E148 Safari/605.1.15', 'Edge', '140'],
    'legacy edge' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19582', 'Edge', '18'],
    'opera desktop' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 OPR/123.0.0.0', 'Opera', '123'],
    'legacy opera' => ['Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18', 'Opera', '12'],
    'samsung internet' => ['Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36', 'Samsung Internet', '28'],
    'firefox desktop' => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0', 'Firefox', '131'],
    'firefox on ios' => ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/143.0 Mobile/15E148 Safari/605.1.15', 'Firefox', '143'],
    'safari desktop' => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15', 'Safari', '17.6'],
    'safari on iphone' => ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1', 'Safari', '18.6'],
]);

test('safari keeps major and minor but drops the patch release', function (): void {
    $ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6.1 Safari/605.1.15';

    expect(BrowserIdentity::fromUserAgent($ua))
        ->name->toBe('Safari')
        ->version->toBe('17.6');
});

test('a safari version with no minor is just the major', function (): void {
    $ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18 Safari/605.1.15';

    expect(BrowserIdentity::fromUserAgent($ua)->version)->toBe('18');
});

test('a version with no dots is still read as the major', function (): void {
    expect(BrowserIdentity::fromUserAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140 Safari/537.36'))
        ->name->toBe('Chrome')
        ->version->toBe('140');
});

test('anything that is not one of the six browsers gives nulls', function (?string $userAgent): void {
    expect(BrowserIdentity::fromUserAgent($userAgent))
        ->name->toBeNull()
        ->version->toBeNull();
})->with([
    'no user agent' => [null],
    'empty user agent' => [''],
    'whitespace' => ['   '],
    'curl' => ['curl/8.7.1'],
    'internet explorer' => ['Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'],
    'arbitrary text' => ['Test Browser'],
]);

test('a crawler claiming chrome is not reported as chrome', function (string $userAgent): void {
    expect(BrowserIdentity::fromUserAgent($userAgent))
        ->name->toBeNull()
        ->version->toBeNull();
})->with([
    'googlebot smartphone' => ['Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.207 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
    'googlebot desktop' => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/140.0.7339.207 Safari/537.36'],
    'bingbot' => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36'],
    'adsbot' => ['Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36 (compatible; AdsBot-Google-Mobile; +http://www.google.com/mobile/adsbot.html)'],
    'headless chrome' => ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/140.0.0.0 Safari/537.36'],
]);

test('a phone whose model name ends in bot is still a browser', function (): void {
    $ua = 'Mozilla/5.0 (Linux; Android 9; CUBOT X20) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36';

    expect(BrowserIdentity::fromUserAgent($ua)->name)->toBe('Chrome');
});

test('a crafted version cannot put arbitrary text on the wire', function (string $userAgent, ?string $version): void {
    expect(BrowserIdentity::fromUserAgent($userAgent)->version)->toBe($version);
})->with([
    'script after the digits' => ['Chrome/140<script>alert(1)</script>', '140'],
    'too many digits to be a version' => ['Chrome/1234567890123456789012345', null],
    'no digits at all' => ['Chrome/abc Safari/537.36', null],
    'a safari minor too long to be one' => ['Version/17.1234567 Safari/605.1.15', '17'],
]);

test('a browser named without a readable version keeps its name', function (): void {
    expect(BrowserIdentity::fromUserAgent('Opera Mini'))
        ->name->toBe('Opera')
        ->version->toBeNull();
});

test('every name and version stays inside the backend bounds', function (string $userAgent): void {
    $browser = BrowserIdentity::fromUserAgent($userAgent);

    expect($browser->name)->toBeIn(['Edge', 'Opera', 'Samsung Internet', 'Firefox', 'Chrome', 'Safari'])
        ->and(mb_strlen((string) $browser->version))->toBeLessThanOrEqual(20)
        ->and($browser->version)->toMatch('/^\d+(\.\d+)?$/');
})->with([
    'long safari' => ['Version/99999.99999.99999 Safari/605.1.15'],
    'long chrome' => ['Chrome/99999.99999.99999.99999'],
]);

test('a huge user agent is read only up to the cap and never throws', function (): void {
    $identifiedFirst = CHROME_DESKTOP_UA.' '.str_repeat('x', 1_000_000);
    $identifiedPastTheCap = str_repeat('x', BrowserIdentity::MAX_USER_AGENT_LENGTH).' '.CHROME_DESKTOP_UA;

    expect(BrowserIdentity::fromUserAgent($identifiedFirst))
        ->name->toBe('Chrome')
        ->version->toBe('140')
        ->and(BrowserIdentity::fromUserAgent($identifiedPastTheCap))
        ->name->toBeNull()
        ->version->toBeNull()
        ->and(BrowserIdentity::fromUserAgent(str_repeat('Opera Version/ Safari/', 100_000)))
        ->name->toBe('Opera');
});

test('invalid utf-8 in a user agent does not stop the match', function (): void {
    expect(BrowserIdentity::fromUserAgent("\xff\xfe ".CHROME_DESKTOP_UA)->name)->toBe('Chrome');
});
