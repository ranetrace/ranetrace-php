<?php

declare(strict_types=1);

use Ranetrace\Php\Config;

test('it ships the documented defaults', function (): void {
    $config = new Config;

    expect($config->get('enabled'))->toBeTrue()
        ->and($config->get('key'))->toBe('')
        ->and($config->get('fingerprint_salt'))->toBeNull()
        ->and($config->get('base_url'))->toBe('https://api.ranetrace.com/v1')
        ->and($config->get('framework'))->toBeNull()
        ->and($config->get('framework_version'))->toBeNull()
        ->and($config->get('user_resolver'))->toBeNull()
        ->and($config->get('flush_on_shutdown'))->toBeTrue();
});

test('it ships the documented feature defaults', function (): void {
    $config = new Config;

    expect($config->get('errors.enabled'))->toBeTrue()
        ->and($config->get('errors.timeout'))->toBe(10)
        ->and($config->get('errors.capture_user_email'))->toBeFalse()
        ->and($config->get('events.enabled'))->toBeTrue()
        ->and($config->get('events.timeout'))->toBe(10)
        ->and($config->get('logging.enabled'))->toBeFalse()
        ->and($config->get('logging.level'))->toBe('notice')
        ->and($config->get('logging.excluded_channels'))->toBe([])
        ->and($config->get('javascript_errors.enabled'))->toBeFalse()
        ->and($config->get('javascript_errors.throttle'))->toBe('60,1')
        ->and($config->get('javascript_errors.sample_rate'))->toBe(1.0)
        ->and($config->get('javascript_errors.capture_console_errors'))->toBeFalse()
        ->and($config->get('javascript_errors.max_breadcrumbs'))->toBe(20)
        ->and($config->get('javascript_errors.allowed_origins'))->toBe([]);
});

test('it ships the documented batch, scrubbing and internal logging defaults', function (): void {
    $config = new Config;

    expect($config->get('batch.buffer_ttl'))->toBe(3600)
        ->and($config->get('batch.max_buffer_size'))->toBe(5000)
        ->and($config->get('batch.lock_wait'))->toBe(1)
        ->and($config->get('scrubbing.extra_keys'))->toBe([])
        ->and($config->get('internal_logging.enabled'))->toBeTrue()
        ->and($config->get('internal_logging.level'))->toBe('debug')
        ->and($config->get('internal_logging.days'))->toBe(14)
        ->and($config->get('internal_logging.stderr_fallback'))->toBeTrue();
});

test('the default ignored javascript errors match the fifteen shipped patterns', function (): void {
    $ignored = (new Config)->get('javascript_errors.ignored_errors');

    expect($ignored)->toHaveCount(15)
        ->and($ignored)->toContain('ResizeObserver loop limit exceeded')
        ->and($ignored)->toContain('Script error.')
        ->and($ignored)->toContain('ChunkLoadError')
        ->and($ignored)->toContain('Illegal invocation');
});

test('buffer path defaults under the system temp directory', function (): void {
    expect((new Config)->get('buffer_path'))->toBe(sys_get_temp_dir().'/ranetrace-buffer');
});

test('project root defaults to the directory holding the composer autoloader', function (): void {
    $root = (new Config)->get('project_root');

    expect($root)->toBeString()
        ->and(is_dir($root))->toBeTrue()
        ->and(is_file($root.'/composer.json'))->toBeTrue();
});

test('environment falls back to APP_ENV and then to production', function (): void {
    withEnv('APP_ENV', 'staging');
    expect((new Config)->get('environment'))->toBe('staging');

    withEnv('APP_ENV', null);
    expect((new Config)->get('environment'))->toBe('production');
});

test('environment variables fill in the keys the config array omits', function (): void {
    withEnv('RANETRACE_KEY', 'env-key');
    withEnv('RANETRACE_ERRORS_TIMEOUT', '25');
    withEnv('RANETRACE_LOGGING_ENABLED', 'true');
    withEnv('RANETRACE_JAVASCRIPT_ERRORS_SAMPLE_RATE', '0.25');
    withEnv('RANETRACE_BASE_URL', 'https://api.example.test/v1');

    $config = new Config;

    expect($config->key())->toBe('env-key')
        ->and($config->get('errors.timeout'))->toBe(25)
        ->and($config->get('logging.enabled'))->toBeTrue()
        ->and($config->get('javascript_errors.sample_rate'))->toBe(0.25)
        ->and($config->get('base_url'))->toBe('https://api.example.test/v1');
});

test('it reads the string spellings an environment file can hold', function (): void {
    withEnv('RANETRACE_ENABLED', 'false');
    withEnv('RANETRACE_ERRORS_ENABLED', '0');
    withEnv('RANETRACE_FINGERPRINT_SALT', 'null');

    $config = new Config;

    expect($config->get('enabled'))->toBeFalse()
        ->and($config->get('errors.enabled'))->toBeFalse()
        ->and($config->get('fingerprint_salt'))->toBeNull();
});

test('list-valued keys accept a comma separated environment variable', function (): void {
    withEnv('RANETRACE_SCRUBBING_EXTRA_KEYS', 'x_signature, internal_seed');
    withEnv('RANETRACE_JAVASCRIPT_ERRORS_ALLOWED_ORIGINS', 'https://a.test,https://b.test');

    $config = new Config;

    expect($config->get('scrubbing.extra_keys'))->toBe(['x_signature', 'internal_seed'])
        ->and($config->get('javascript_errors.allowed_origins'))->toBe(['https://a.test', 'https://b.test']);
});

test('the config array wins over the environment', function (): void {
    withEnv('RANETRACE_KEY', 'env-key');
    withEnv('RANETRACE_ERRORS_TIMEOUT', '25');

    $config = new Config(['key' => 'array-key', 'errors' => ['timeout' => 3]]);

    expect($config->key())->toBe('array-key')
        ->and($config->get('errors.timeout'))->toBe(3);
});

test('it reads nested values by dot key and returns the fallback for anything missing', function (): void {
    $config = new Config(['logging' => ['level' => 'warning']]);

    expect($config->get('logging.level'))->toBe('warning')
        ->and($config->get('logging.nope'))->toBeNull()
        ->and($config->get('logging.nope', 'fallback'))->toBe('fallback')
        ->and($config->get('nope.nope.nope', 7))->toBe(7);
});

test('unknown keys are kept rather than rejected, so a newer host config still boots', function (): void {
    $config = new Config(['future_feature' => ['enabled' => true, 'mode' => 'fast']]);

    expect($config->get('future_feature.mode'))->toBe('fast')
        ->and($config->get('errors.timeout'))->toBe(10);
});

test('enabled requires the master switch, the feature switch and a key', function (): void {
    expect((new Config(['key' => 'k']))->enabled('errors'))->toBeTrue()
        ->and((new Config(['key' => 'k']))->enabled())->toBeTrue()
        ->and((new Config(['key' => '']))->enabled('errors'))->toBeFalse()
        ->and((new Config(['key' => 'k', 'enabled' => false]))->enabled('errors'))->toBeFalse()
        ->and((new Config(['key' => 'k']))->enabled('logging'))->toBeFalse()
        ->and((new Config(['key' => 'k', 'logging' => ['enabled' => true]]))->enabled('logging'))->toBeTrue();
});

test('enabled is false for a feature the config does not know', function (): void {
    expect((new Config(['key' => 'k']))->enabled('page_visits'))->toBeFalse();
});

test('key returns an empty string when nothing configured one', function (): void {
    expect((new Config)->key())->toBe('')
        ->and((new Config(['key' => null]))->key())->toBe('');
});

test('a non-string key is a loud configuration error', function (): void {
    new Config(['key' => 12345]);
})->throws(InvalidArgumentException::class, 'must be a string');

test('a user resolver that is not callable is a loud configuration error', function (): void {
    new Config(['user_resolver' => 'not-a-function']);
})->throws(InvalidArgumentException::class, 'must be callable or null');

test('a callable user resolver is accepted and returned as given', function (): void {
    $resolver = static fn (): array => ['id' => 7, 'email' => null];

    $config = new Config(['key' => 'k', 'user_resolver' => $resolver]);

    expect($config->get('user_resolver'))->toBe($resolver)
        ->and(($config->get('user_resolver'))())->toBe(['id' => 7, 'email' => null]);
});

test('framework identity is configurable from the array or the environment', function (): void {
    withEnv('RANETRACE_FRAMEWORK', 'symfony');
    withEnv('RANETRACE_FRAMEWORK_VERSION', '7.2.1');

    expect((new Config)->get('framework'))->toBe('symfony')
        ->and((new Config)->get('framework_version'))->toBe('7.2.1')
        ->and((new Config(['framework' => 'slim']))->get('framework'))->toBe('slim');
});

test('all returns the resolved config including unknown keys', function (): void {
    $all = (new Config(['key' => 'k', 'custom' => 1]))->all();

    expect($all['key'])->toBe('k')
        ->and($all['custom'])->toBe(1)
        ->and($all['batch']['max_buffer_size'])->toBe(5000);
});
