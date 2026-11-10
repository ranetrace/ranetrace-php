/**
 * A stand-in browser page for the capture script, run by
 * tests/Unit/JavaScriptCaptureScriptBehaviourTest.php.
 *
 *     node browser.js <rendered script> <events as JSON>
 *
 * It runs the rendered script in a page that has just enough of a browser for it
 * to start, fires the given `error` events at the listeners the script put on
 * `window`, and prints the reports the script posted as a JSON list.
 *
 * An event names its target as "window" (a script error) or "element" (a
 * resource that failed to load, which a browser fires on the element itself and
 * a capture-phase listener on `window` receives too). An `error` of
 * `{name, message}` becomes an error object.
 */
'use strict';

const fs = require('node:fs');
const vm = require('node:vm');

const [scriptPath, eventsJson] = process.argv.slice(2);

const listeners = [];
const reports = [];

const page = {
    addEventListener(type, listener) {
        listeners.push({ type, listener });
    },
    document: { addEventListener() {} },
    navigator: {},
    screen: { width: 1280, height: 720 },
    innerWidth: 1280,
    innerHeight: 720,
    location: { href: 'https://shop.test/checkout' },
    console: { warn() {}, error() {} },
    fetch(url, options) {
        reports.push(JSON.parse(options.body));

        return Promise.resolve({ status: 200 });
    },
};

// In a browser the global object is the window, so `window.fetch` and a bare
// `fetch` are one thing. The script relies on that when it wraps fetch.
page.window = page;

vm.createContext(page);
vm.runInContext(fs.readFileSync(scriptPath, 'utf8'), page);

// The script sees the page as its global object, which node hands out under
// another identity than `page` has out here. An event fired on the window has to
// carry the one the script compares against.
const windowAsTheScriptSeesIt = vm.runInContext('window', page);
const element = { tagName: 'SCRIPT', src: 'https://tags.test/blocked.js' };

for (const described of JSON.parse(eventsJson)) {
    const event = {
        ...described,
        type: 'error',
        target: described.target === 'window' ? windowAsTheScriptSeesIt : element,
    };

    if (described.error) {
        event.error = Object.assign(new Error(described.error.message), { name: described.error.name });
    }

    for (const { type, listener } of listeners) {
        if (type === 'error') {
            listener(event);
        }
    }
}

process.stdout.write(JSON.stringify(reports));
