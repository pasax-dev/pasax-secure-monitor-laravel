<?php

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Pasax\SecureMonitor\Models\BlockedIp;
use Pasax\SecureMonitor\Models\SecurityLog;
use Pasax\SecureMonitor\Services\PasaxCloudService;

beforeEach(function () {
    Cache::flush();
    config()->set('app.name', 'Laravel');
    config()->set('app.url', 'http://localhost:8000');
    config()->set('pasax.cloud.enabled', true);
    config()->set('pasax.cloud.key', 'psk_live_test1234567890abcdef');
    config()->set('pasax.cloud.url', 'https://mock-cloud.pasax.test');
});

test('cloud service extracts metadata from APP_NAME and APP_URL', function () {
    $cloud = app(PasaxCloudService::class);
    $meta = $cloud->getAppMetadata();

    expect($meta['name'])
        ->toBe('Laravel')
        ->and($meta['url'])
        ->toBe('http://localhost:8000')
        ->and($meta['host'])
        ->toBe('localhost')
        ->and($meta['is_https'])
        ->toBeFalse();
});

test('cloud service validates isConfigured based on key format', function () {
    $cloud = app(PasaxCloudService::class);
    expect($cloud->isConfigured())->toBeTrue();
    expect($cloud->getMaskedKey())->toContain('psk_live');

    config()->set('pasax.cloud.key', null);
    $emptyCloud = new PasaxCloudService;
    expect($emptyCloud->isConfigured())->toBeFalse();
});

test('cloud service can send heartbeat and report threat event', function () {
    Http::fake([
        'https://mock-cloud.pasax.test/api/v1/nodes/telemetry' => Http::response(
            [
                'status' => 'acknowledged',
                'node_id' => 'nod_mock_123',
            ],
            200,
        ),
        'https://mock-cloud.pasax.test/api/v1/events/threat' => Http::response(
            [
                'status' => 'success',
                'event_id' => 'evt_123',
            ],
            200,
        ),
        'https://mock-cloud.pasax.test/api/v1/threats/global-blocklist' => Http::response(
            [
                'ips' => ['198.51.100.99', '203.0.113.88'],
            ],
            200,
        ),
    ]);

    $cloud = app(PasaxCloudService::class);

    $hb = $cloud->sendHeartbeat();
    expect($hb['success'])
        ->toBeTrue()
        ->and($hb['app_name'])
        ->toBe('Laravel')
        ->and($hb['app_url'])
        ->toBe('http://localhost:8000');

    $reported = $cloud->reportThreat([
        'event_type' => 'sql_injection',
        'ip_address' => '198.51.100.42',
        'threat_level' => 'critical',
    ]);
    expect($reported)->toBeTrue();

    $blocklist = $cloud->fetchGlobalBlocklist();
    expect($blocklist)
        ->toHaveCount(2)
        ->and($blocklist)
        ->toContain('198.51.100.99');
});

test(
    'verifyLicense succeeds and marks protection active for valid 14-day pro trial',
    function () {
        Http::fake([
            'https://mock-cloud.pasax.test/api/licenses/verify' => Http::response(
                [
                    'valid' => true,
                    'status' => 'trialing',
                    'is_trial' => true,
                    'remaining_days' => 12,
                    'tier' => 'pro',
                    'protection_mode' => 'active',
                ],
                200,
            ),
        ]);

        $cloud = app(PasaxCloudService::class);
        $verification = $cloud->verifyLicense(true);

        expect($verification['valid'])
            ->toBeTrue()
            ->and($verification['protection_mode'])
            ->toBe('active')
            ->and($verification['is_trial'])
            ->toBeTrue()
            ->and($verification['remaining_days'])
            ->toBe(12)
            ->and($cloud->isProtectionActive())
            ->toBeTrue()
            ->and($cloud->isTrialExpired())
            ->toBeFalse();
    },
);

test(
    'verifyLicense disables protection and activates passive mode when trial is expired',
    function () {
        Http::fake([
            'https://mock-cloud.pasax.test/api/licenses/verify' => Http::response(
                [
                    'valid' => false,
                    'status' => 'expired',
                    'is_trial' => true,
                    'remaining_days' => 0,
                    'protection_mode' => 'disabled',
                    'threat_count_only' => true,
                    'total_threats_observed' => 1420,
                    'message' => 'Masa percobaan 14 hari telah habis. Perlindungan dinonaktifkan.',
                ],
                200,
            ),
        ]);

        $cloud = app(PasaxCloudService::class);
        $verification = $cloud->verifyLicense(true);

        expect($verification['valid'])
            ->toBeFalse()
            ->and($verification['status'])
            ->toBe('expired')
            ->and($verification['protection_mode'])
            ->toBe('disabled')
            ->and($verification['threat_count_only'])
            ->toBeTrue()
            ->and($cloud->isProtectionActive())
            ->toBeFalse()
            ->and($cloud->isTrialExpired())
            ->toBeTrue();
    },
);

test('middleware allows attack through without 403 when trial is expired (passive mode)', function () {
    config()->set('pasax.instant_block.enabled', true);

    Http::fake([
        'https://mock-cloud.pasax.test/api/licenses/verify' => Http::response([
            'valid' => false,
            'status' => 'expired',
            'protection_mode' => 'disabled',
            'threat_count_only' => true,
        ], 200),
        'https://mock-cloud.pasax.test/api/v1/events/threat' => Http::response(['status' => 'success'], 200),
    ]);

    $response = $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.77'])
        ->get('/?test=%27+OR+1%3D1--');

    $response->assertOk();

    expect(BlockedIp::query()->where('ip_address', '198.51.100.77')->exists())->toBeFalse();

    $log = SecurityLog::query()->where('ip_address', '198.51.100.77')->first();
    expect($log)->not->toBeNull()
        ->and($log->action_taken)->toBe('unprotected_passive');
});
