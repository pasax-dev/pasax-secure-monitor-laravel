<?php

use Illuminate\Support\Facades\File;
use Pasax\SecureMonitor\Console\Commands\PasaxInstallCommand;

$tempDir = '';

beforeEach(function () use (&$tempDir) {
    $tempDir = sys_get_temp_dir().'/pasax_install_license_test_'.uniqid();
    File::makeDirectory($tempDir, 0755, true, true);
    File::put($tempDir.'/.env', "APP_NAME=Laravel\nAPP_KEY=base64:xxx\n");
});

afterEach(function () use (&$tempDir) {
    if (! empty($tempDir) && File::isDirectory($tempDir)) {
        File::deleteDirectory($tempDir);
    }
});

test('pasax install command defines api-key and api-url options', function () {
    $command = app(PasaxInstallCommand::class);
    $definition = $command->getDefinition();

    expect($definition->hasOption('api-key'))->toBeTrue();
    expect($definition->hasOption('api-url'))->toBeTrue();
    expect($definition->hasOption('skip-cloud-verify'))->toBeTrue();
});

test(
    'pasax install fails when server cannot connect to cloud api (offline/unreachable)',
    function () {
        // Port 59998 is not listening -> simulates offline/network error
        $this->artisan('pasax:install', [
            '--api-key' => 'psk_live_test_unreachable_key',
            '--api-url' => 'http://127.0.0.1:59998',
            '--no-interaction' => true,
        ])
            ->expectsOutputToContain(
                'Server tidak memiliki koneksi internet aktif',
            )
            ->assertExitCode(1);
    },
);

test(
    'pasax install can bypass cloud verification with skip-cloud-verify',
    function () {
        $this->artisan('pasax:install', [
            '--skip-cloud-verify' => true,
            '--without-nginx' => true,
            '--without-apache' => true,
            '--without-htaccess' => true,
            '--without-views' => true,
            '--without-user-trait' => true,
            '--without-middleware' => true,
            '--without-routes' => true,
            '--without-skills' => true,
            '--no-interaction' => true,
        ])->assertSuccessful();
    },
);

test(
    'injectLicenseKeysIntoEnvContent correctly updates or injects license keys and cloud url',
    function () {
        $command = new class extends PasaxInstallCommand
        {
            public function testInject(
                string $content,
                string $key,
                string $url,
            ): string {
                return $this->injectLicenseKeysIntoEnvContent(
                    $content,
                    $key,
                    $url,
                );
            }
        };

        $initialEnv = <<<'ENV'
        APP_NAME=Laravel
        PASAX_LICENSE_KEY=
        PASAX_API_URL=https://service.pasax.web.id
        PASAX_CLOUD_KEY=
        ENV;

        $updated = $command->testInject(
            $initialEnv,
            'psk_live_1234567890abcdef',
            'https://custom-service.pasax.test',
        );

        expect($updated)
            ->toContain('PASAX_LICENSE_KEY=psk_live_1234567890abcdef')
            ->and($updated)
            ->toContain('PASAX_CLOUD_KEY=psk_live_1234567890abcdef')
            ->and($updated)
            ->toContain('PASAX_API_URL=https://custom-service.pasax.test');
    },
);
