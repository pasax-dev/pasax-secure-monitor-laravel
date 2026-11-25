<?php

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Route;
use Pasax\SecureMonitor\Console\Commands\PasaxInstallCommand;
use Pasax\SecureMonitor\Models\PasaxSetting;
use Pasax\SecureMonitor\Support\PasaxDashboardSecret;
use Pasax\SecureMonitor\Tests\TestUser;

beforeEach(function () {
    config()->set('pasax.dashboard.enabled', true);
    config()->set('pasax.dashboard.auth.enabled', true);
    config()->set('pasax.dashboard.rotating', false);
    config()->set('pasax.dashboard.auth.username', 'admin');
    config()->set('pasax.dashboard.auth.default_password', 'Admin');
    config()->set('pasax.dashboard.auth.owner_email', 'owner@pasax.web.id');
    config()->set('pasax.dashboard.auth.owner_username', 'owneracct');
    config()->set('pasax.dashboard.auth.passwordless_owner', true);
    config()->set('pasax.cloud.license_key', 'psk_live_test_owner_signing_key_2026');
    config()->set('pasax.cloud.key', 'psk_live_test_owner_signing_key_2026');

    $viewsTarget = resource_path('views/pages/pasax');
    File::ensureDirectoryExists($viewsTarget);
    File::copyDirectory(
        dirname(__DIR__, 2).'/stubs/blade/pages/pasax',
        $viewsTarget,
    );

    require __DIR__.'/../../routes/pasax-web-blade.php';
    Route::getRoutes()->refreshNameLookups();

    $envPath = base_path('.env');
    $secret = 'test-secret-key-1234567890abcdefghijklmnopqrstuvwxyz';
    File::put(
        $envPath,
        "PASAX_DASHBOARD_USERNAME=admin\nPASAX_DASHBOARD_PASSWORD=Admin\nPASAX_DASHBOARD_SECRET={$secret}\nPASAX_OWNER_EMAIL=owner@pasax.web.id\nPASAX_OWNER_USERNAME=owneracct\nPASAX_DASHBOARD_PASSWORDLESS_OWNER=true\nPASAX_LICENSE_KEY=psk_live_test_owner_signing_key_2026\n",
    );

    PasaxSetting::query()->whereIn('key', [
        PasaxDashboardSecret::DB_OWNER_EMAIL_KEY,
        PasaxDashboardSecret::DB_OWNER_USERNAME_KEY,
        PasaxDashboardSecret::DB_OWNER_NAME_KEY,
        PasaxDashboardSecret::DB_OWNER_PLAN_KEY,
    ])->delete();
});

afterEach(function () {
    $envPath = base_path('.env');
    if (File::exists($envPath)) {
        File::delete($envPath);
    }
});

test('verified host owner user enters pasax dashboard passwordlessly and explicit logout enables one-click re-entry', function () {
    $owner = TestUser::create([
        'name' => 'Pasax Owner',
        'email' => 'owner@pasax.web.id',
        'password' => bcrypt('host-password'),
        'role' => 'admin',
    ]);

    // Automatic passwordless entry for authenticated host owner
    $resp = $this->actingAs($owner)->get('/pasax');
    $resp->assertOk();
    expect(session('pasax_dashboard_authenticated'))->toBeTrue()
        ->and(session('pasax_dashboard_auth_mode'))->toBe('owner_session')
        ->and(session('pasax_dashboard_user'))->toBe('owneracct');

    // Explicit logout sets pasax_dashboard_logged_out and stops auto-entry
    $logoutResp = $this->actingAs($owner)
        ->withSession(['pasax_dashboard_authenticated' => true])
        ->post(route('pasax.dashboard.logout'));

    $logoutResp->assertRedirect(route('pasax.dashboard.login'));
    expect(session('pasax_dashboard_logged_out'))->toBeTrue()
        ->and(session('pasax_dashboard_authenticated'))->toBeNull();

    // Accessing /pasax again while logged out redirects to login instead of auto-bypassing
    $afterLogout = $this->actingAs($owner)
        ->withSession(['pasax_dashboard_logged_out' => true])
        ->get('/pasax');
    $afterLogout->assertRedirect(route('pasax.dashboard.login'));

    // Login screen offers verified one-click owner button
    $loginPage = $this->actingAs($owner)->get(route('pasax.dashboard.login'));
    $loginPage->assertOk()
        ->assertSee(route('pasax.dashboard.login.owner'), false)
        ->assertSee('owneracct');

    // One-click owner re-login restores passwordless dashboard session
    $ownerLogin = $this->actingAs($owner)
        ->withSession(['pasax_dashboard_logged_out' => true])
        ->post(route('pasax.dashboard.login.owner'));

    $ownerLogin->assertRedirect('/pasax');
    expect(session('pasax_dashboard_authenticated'))->toBeTrue()
        ->and(session('pasax_dashboard_auth_mode'))->toBe('owner_session')
        ->and(session('pasax_dashboard_logged_out'))->toBeNull();
});

test('non-owner host user and raw unauthenticated requests cannot enter passwordlessly', function () {
    $otherUser = TestUser::create([
        'name' => 'Other Admin',
        'email' => 'intruder@example.com',
        'password' => bcrypt('other-pass'),
        'role' => 'admin',
    ]);

    // Non-owner host user is NOT granted owner_session access
    $this->actingAs($otherUser)
        ->get('/pasax')
        ->assertRedirect(route('pasax.dashboard.login'));

    $this->actingAs($otherUser)
        ->postJson(route('pasax.dashboard.login.owner'))
        ->assertStatus(403);

    // Guest cannot hit login.owner
    $this->postJson(route('pasax.dashboard.login.owner'))
        ->assertStatus(403);

    // Username without password is still rejected on form login
    $this->post(route('pasax.dashboard.login.submit'), [
        'username' => 'owneracct',
    ])->assertSessionHasErrors('password');
});

test('signed owner sso token authenticates valid token and rejects expired or tampered tokens', function () {
    $validToken = PasaxDashboardSecret::generateOwnerSsoToken('owner@pasax.web.id', 300);

    $ssoResponse = $this->get(route('pasax.dashboard.login', ['sso_token' => $validToken]));
    $ssoResponse->assertRedirect('/pasax');
    expect(session('pasax_dashboard_authenticated'))->toBeTrue()
        ->and(session('pasax_dashboard_auth_mode'))->toBe('owner_sso')
        ->and(session('pasax_dashboard_user'))->toBe('owner@pasax.web.id');

    // Tampered token fails cleanly
    $this->withSession([])->flushSession();
    $tampered = $validToken.'x';
    $tamperedResp = $this->get(route('pasax.dashboard.login', ['sso_token' => $tampered]));
    $tamperedResp->assertOk()
        ->assertSee('tidak valid atau telah kedaluwarsa');
    expect(session('pasax_dashboard_authenticated'))->toBeNull();

    // Expired token fails cleanly
    $expiredPayload = rtrim(strtr(base64_encode(json_encode([
        'sub' => 'owner@pasax.web.id',
        'iat' => time() - 600,
        'exp' => time() - 60,
        'nonce' => 'abcdef0123456789',
    ])), '+/', '-_'), '=');
    $expiredSig = rtrim(strtr(base64_encode(hash_hmac(
        'sha256',
        $expiredPayload,
        'psk_live_test_owner_signing_key_2026',
        true,
    )), '+/', '-_'), '=');
    $expiredResp = $this->get(route('pasax.dashboard.login', [
        'sso_token' => $expiredPayload.'.'.$expiredSig,
    ]));
    $expiredResp->assertOk()
        ->assertSee('tidak valid atau telah kedaluwarsa');
    expect(session('pasax_dashboard_authenticated'))->toBeNull();

    // Wrong subject signed with valid secret fails cleanly
    $wrongSub = PasaxDashboardSecret::generateOwnerSsoToken('attacker@evil.test', 300);
    $this->get(route('pasax.dashboard.login', ['sso_token' => $wrongSub]))
        ->assertOk()
        ->assertSee('tidak valid atau telah kedaluwarsa');
    expect(session('pasax_dashboard_authenticated'))->toBeNull();
});

test('pasax install command persists owner identity and isolated database env keys after mocked cloud verify', function () {
    $envPath = base_path('.env');
    File::put($envPath, "APP_NAME=Laravel\nAPP_KEY=base64:xxx\n");

    $fakeInstallCommand = new class extends PasaxInstallCommand
    {
        protected function makeHttpRequest(string $method, string $url, array $payload = [], array $headers = [], int $timeout = 6): array
        {
            if (str_contains($url, '/api/v1/health')) {
                return ['status' => 200, 'body' => json_encode(['status' => 'ok'])];
            }

            if (str_contains($url, '/api/v1/auth/verify')) {
                return [
                    'status' => 200,
                    'body' => json_encode([
                        'valid' => true,
                        'data' => [
                            'user' => [
                                'name' => 'Roby Kartis',
                                'email' => 'roby@pasax.web.id',
                                'username' => 'robykartis',
                                'plan' => 'enterprise',
                            ],
                            'license_key' => [
                                'name' => 'Production Main Key',
                            ],
                        ],
                    ]),
                ];
            }

            return ['status' => 404, 'body' => ''];
        }
    };

    app()->instance(PasaxInstallCommand::class, $fakeInstallCommand);
    $artisan = app(Kernel::class);
    if (method_exists($artisan, 'registerCommand')) {
        $artisan->registerCommand($fakeInstallCommand);
    }

    $this->artisan('pasax:install', [
        '--api-key' => 'psk_live_mocked_install_key_999',
        '--api-url' => 'https://service.pasax.web.id',
        '--without-nginx' => true,
        '--without-apache' => true,
        '--without-htaccess' => true,
        '--without-views' => true,
        '--without-user-trait' => true,
        '--without-middleware' => true,
        '--without-routes' => true,
        '--without-skills' => true,
        '--no-interaction' => true,
    ])
        ->expectsOutputToContain('Akun pemilik terikat: robykartis <roby@pasax.web.id>')
        ->assertSuccessful();

    $envContent = File::get($envPath);
    expect($envContent)
        ->toContain('PASAX_DB_CONNECTION=pasax_sqlite')
        ->toContain('PASAX_DB_PATH=storage/app/pasax/pasax.sqlite')
        ->toContain('PASAX_DB_BACKUP_PATH=storage/app/pasax/backups')
        ->toContain('PASAX_LICENSE_KEY=psk_live_mocked_install_key_999')
        ->toContain('PASAX_OWNER_EMAIL=roby@pasax.web.id')
        ->toContain('PASAX_OWNER_USERNAME=robykartis')
        ->toContain('PASAX_DASHBOARD_PASSWORDLESS_OWNER=true');

    expect(PasaxSetting::query()->where('key', PasaxDashboardSecret::DB_OWNER_EMAIL_KEY)->value('value'))->toBe('roby@pasax.web.id')
        ->and(PasaxSetting::query()->where('key', PasaxDashboardSecret::DB_OWNER_USERNAME_KEY)->value('value'))->toBe('robykartis')
        ->and(PasaxSetting::query()->where('key', PasaxDashboardSecret::DB_OWNER_PLAN_KEY)->value('value'))->toBe('ENTERPRISE');
});
