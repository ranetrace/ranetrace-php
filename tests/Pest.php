<?php

declare(strict_types=1);

use Ranetrace\Php\Config;
use Ranetrace\Php\JavaScript\CaptureScript;
use Ranetrace\Php\Tests\TestCase;

uses(TestCase::class)->in('Unit', 'Feature', 'Contract');

/**
 * What the endpoints' `uuid` rule accepts for an item's `id`.
 */
const UUID_V4_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D';

/**
 * Environment variables a test set, so they can be removed again afterwards.
 * Config reads `$_ENV`, `$_SERVER` and `getenv()`, so all three are cleared.
 *
 * @var array<int, string>
 */
$GLOBALS['ranetrace_test_env_keys'] = [];

/**
 * Temporary directories a test created, removed after the test.
 *
 * @var array<int, string>
 */
$GLOBALS['ranetrace_test_temp_dirs'] = [];

uses()->afterEach(function (): void {
    foreach ($GLOBALS['ranetrace_test_env_keys'] as $name) {
        unset($_ENV[$name], $_SERVER[$name]);
        putenv($name);
    }

    $GLOBALS['ranetrace_test_env_keys'] = [];

    foreach ($GLOBALS['ranetrace_test_temp_dirs'] as $directory) {
        deleteTempDirectory($directory);
    }

    $GLOBALS['ranetrace_test_temp_dirs'] = [];
})->in('Unit', 'Feature', 'Contract');

/**
 * Whether this process runs as root, or cannot tell. A test that emulates
 * another user by taking this process's access away by file mode skips then,
 * because root ignores modes.
 */
function runsAsRoot(): bool
{
    return ! function_exists('posix_geteuid') || posix_geteuid() === 0;
}

/**
 * Run $run while the `errors.lock` file in $directory is read-only, as one that
 * another user owns, and return what it returned. The file is created when
 * missing and made writable again afterwards, so it can be cleaned up.
 */
function withForeignLockFile(string $directory, callable $run): mixed
{
    touch($directory.'/errors.lock');
    chmod($directory.'/errors.lock', 0444);

    try {
        return $run();
    } finally {
        chmod($directory.'/errors.lock', 0600);
    }
}

/**
 * Spool one item of $type into the buffer in $directory, captured $age seconds
 * ago, and return the JSON written to its file.
 */
function spoolItem(string $directory, string $type = 'errors', string $message = 'spooled', int $age = 0): string
{
    $spooled = (string) json_encode([
        ['id' => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'data' => ['message' => $message], 'timestamp' => time() - $age],
    ]);

    file_put_contents($directory.'/'.$type.'.json', $spooled);

    return $spooled;
}

/**
 * Set an environment variable for the duration of one test.
 */
function withEnv(string $name, ?string $value): void
{
    $GLOBALS['ranetrace_test_env_keys'][] = $name;

    if ($value === null) {
        unset($_ENV[$name], $_SERVER[$name]);
        putenv($name);

        return;
    }

    $_ENV[$name] = $value;
    putenv($name.'='.$value);
}

/**
 * A fresh, empty directory under the system temp dir, removed after the test.
 */
function tempDirectory(string $prefix = 'ranetrace-test-'): string
{
    $directory = sys_get_temp_dir().'/'.$prefix.bin2hex(random_bytes(6));

    mkdir($directory, 0775, true);

    $GLOBALS['ranetrace_test_temp_dirs'][] = $directory;

    return $directory;
}

/**
 * Everything the internal logger wrote into $directory: every `internal-*.log`
 * file there, joined in name order.
 */
function internalLogContents(string $directory): string
{
    $files = glob($directory.'/internal-*.log') ?: [];

    return implode('', array_map(static fn (string $file): string => (string) file_get_contents($file), $files));
}

function deleteTempDirectory(string $directory): void
{
    if (! is_dir($directory)) {
        return;
    }

    $entries = glob($directory.'/*') ?: [];

    foreach ($entries as $entry) {
        // A symlink is removed as itself: following one into a directory would
        // empty its target and then fail to rmdir the link.
        if (is_dir($entry) && ! is_link($entry)) {
            deleteTempDirectory($entry);

            continue;
        }

        @unlink($entry);
    }

    @rmdir($directory);
}

/**
 * A Config with a usable API key, so `enabled()` gates open by default.
 *
 * @param  array<string, mixed>  $overrides
 */
function testConfig(array $overrides = []): Config
{
    return new Config(array_replace(['key' => 'test-api-key-12345'], $overrides));
}

/**
 * The runtime config object out of a rendered capture script.
 *
 * The script ships minified, so the variable the config is assigned to is a
 * one-letter name that a different esbuild version may spell differently, and no
 * test may key on it. The literal is located by the template around it instead: a
 * probe render gives the exact prefix and suffix the substitution sits between,
 * whatever the minifier called things.
 *
 * `$rendered` may be the bare script or a whole page with the script inside it.
 *
 * @return array<string, mixed>
 */
function capturedScriptConfig(string $rendered): array
{
    [$before, $after] = explode(
        '{"ranetraceProbe":true}',
        CaptureScript::withConfig(['ranetraceProbe' => true]),
        2,
    );

    $start = mb_strpos($rendered, $before);

    expect($start)->not->toBeFalse('the rendered output does not carry the capture script');

    $start += mb_strlen($before);
    $end = mb_strpos($rendered, $after, $start);

    expect($end)->not->toBeFalse('the capture script is truncated after the config literal');

    return json_decode(mb_substr($rendered, $start, $end - $start), true, 512, JSON_THROW_ON_ERROR);
}

/**
 * A throwaway project root for the frame tests: a fresh temp directory under
 * its real path, since PHP names an included file by its real path and the
 * builder compares frame files against the root byte for byte.
 */
function frameProject(): string
{
    return (string) realpath(tempDirectory('ranetrace-frames-'));
}

/**
 * Write a file into a frame-test project and return its absolute path.
 */
function writeProjectFile(string $root, string $relative, string $contents): string
{
    $path = $root.'/'.$relative;

    if (! is_dir(dirname($path))) {
        mkdir(dirname($path), 0775, true);
    }

    file_put_contents($path, $contents);

    return $path;
}

/**
 * A PayloadBuilder rooted at $root, with internal logging written into the
 * root's own `diagnostics` directory so a test can read what it logged.
 *
 * @param  array<string, mixed>  $overrides
 * @param  list<Ranetrace\Php\Errors\FrameMapper>  $mappers
 */
function frameBuilder(string $root, array $overrides = [], array $mappers = [], ?Ranetrace\Php\Support\Scrubber $scrubber = null): Ranetrace\Php\Errors\PayloadBuilder
{
    $config = testConfig(array_replace_recursive([
        'project_root' => $root,
        'buffer_path' => $root.'/diagnostics',
        'internal_logging' => ['enabled' => true, 'level' => 'debug', 'stderr_fallback' => false],
    ], $overrides));
    $log = new Ranetrace\Php\Support\InternalLogger($config);

    return new Ranetrace\Php\Errors\PayloadBuilder($config, $scrubber ?? new Ranetrace\Php\Support\SecretScrubber($config, $log), $log, $mappers);
}

/**
 * The item a frame-test builder makes of $throwable, in a console context.
 *
 * @return array<string, mixed>
 */
function framePayload(Ranetrace\Php\Errors\PayloadBuilder $builder, Throwable $throwable): array
{
    return $builder->build($throwable, Ranetrace\Php\Errors\ErrorContext::provided(isConsole: true));
}

/**
 * What a frame-test builder wrote to its diagnostics log.
 */
function frameDiagnostics(string $root): string
{
    return internalLogContents($root.'/diagnostics');
}

/**
 * Run $callback in a project file that recurses $depth times before throwing,
 * and return what it threw.
 */
function deepRecursionException(string $root, int $depth, string $padding = ''): RuntimeException
{
    $recurse = require writeProjectFile($root, 'app/Recurse.php', <<<PHP
        <?php

        \$recurse = static function (int \$depth) use (&\$recurse): void { // {$padding}
            if (\$depth === 0) { // {$padding}
                throw new RuntimeException('bottom'); // {$padding}
            } // {$padding}

            \$recurse(\$depth - 1); // {$padding}
        }; // {$padding}

        return \$recurse;

        PHP);

    try {
        $recurse($depth);
    } catch (RuntimeException $exception) {
        return $exception;
    }

    throw new LogicException('The recursion did not throw.');
}

/**
 * Run a PHP script of this package in a subprocess, from the package root.
 * The subprocess sees this process's environment with $environment over it.
 *
 * @param  array<int, string>  $arguments  The script's path, then its arguments.
 * @param  array<string, string>  $environment
 * @return array{status: int, stdout: string, stderr: string}
 */
function runPhp(array $arguments, array $environment = []): array
{
    $process = proc_open(
        array_merge([PHP_BINARY], $arguments),
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        dirname(__DIR__),
        array_merge(getenv(), $environment),
    );

    if (! is_resource($process)) {
        return ['status' => 1, 'stdout' => '', 'stderr' => 'could not start subprocess'];
    }

    $stdout = (string) stream_get_contents($pipes[1]);
    $stderr = (string) stream_get_contents($pipes[2]);

    fclose($pipes[1]);
    fclose($pipes[2]);

    return ['status' => proc_close($process), 'stdout' => $stdout, 'stderr' => $stderr];
}

/**
 * Run $run against `tests/Doubles/fake-api.php` on PHP's built-in server, and
 * return what it returned beside every request the server received.
 *
 * @param  callable(array<string, string>): mixed  $run  Given the environment that points a subprocess at the server.
 * @param  array<string, string>  $serverEnvironment
 * @return array{result: mixed, requests: list<array{path: string, user_agent: string, body: string}>}
 */
function againstFakeApi(callable $run, array $serverEnvironment = []): array
{
    $probe = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) mb_substr((string) mb_strrchr((string) stream_socket_get_name($probe, false), ':'), 1);
    fclose($probe);

    $record = tempDirectory().'/requests.jsonl';

    $server = proc_open(
        [PHP_BINARY, '-S', "127.0.0.1:{$port}", 'tests/Doubles/fake-api.php'],
        [1 => ['file', '/dev/null', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        dirname(__DIR__),
        array_merge(getenv(), ['FAKE_API_RECORD' => $record], $serverEnvironment),
    );

    try {
        // The built-in server writes one line to stderr once it listens.
        fgets($pipes[2]);

        $result = $run(['RANETRACE_BASE_URL' => "http://127.0.0.1:{$port}/v1"]);
    } finally {
        if (is_resource($server)) {
            proc_terminate($server);
            proc_close($server);
        }
    }

    $lines = is_file($record) ? array_filter(explode("\n", (string) file_get_contents($record))) : [];

    return [
        'result' => $result,
        'requests' => array_values(array_map(static fn (string $line): array => json_decode($line, true), $lines)),
    ];
}
