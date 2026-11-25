<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Route;
use Pasax\SecureMonitor\Models\PasaxBlockedIp;
use Pasax\SecureMonitor\Models\PasaxLog;
use Pasax\SecureMonitor\Support\PasaxDatabase;
use Pasax\SecureMonitor\Support\PasaxTableResolver;

$backupTempDir = '';

beforeEach(function () use (&$backupTempDir) {
    $backupTempDir = sys_get_temp_dir().'/pasax_backup_test_'.uniqid();
    File::makeDirectory($backupTempDir, 0755, true, true);

    DB::purge('pasax_sqlite');
    PasaxTableResolver::clearCache();

    config()->set('pasax.database.connection', 'pasax_sqlite');
    config()->set('pasax.database.path', $backupTempDir.'/pasax/pasax.sqlite');
    config()->set('pasax.database.backup_path', $backupTempDir.'/pasax/backups');
    config()->set('pasax.database.sqlite_wal', true);

    config()->set('pasax.dashboard.enabled', true);
    config()->set('pasax.dashboard.auth.enabled', true);
    config()->set('pasax.dashboard.rotating', false);
    config()->set('pasax.dashboard.auth.owner_username', 'roby');
    config()->set('pasax.dashboard.auth.owner_email', 'roby@pasax.web.id');

    PasaxDatabase::prepareForMigration();

    $this->artisan('migrate', [
        '--database' => 'pasax_sqlite',
        '--path' => realpath(__DIR__.'/../../database/migrations'),
        '--realpath' => true,
        '--force' => true,
    ])->assertSuccessful();

    PasaxLog::query()->create([
        'ip_address' => '203.0.113.77',
        'event_type' => 'sqli',
        'threat_level' => 'critical',
        'path' => '/login',
        'full_url' => 'https://app.test/login',
        'method' => 'POST',
        'evidence' => 'SQLi backup verification row',
    ]);

    PasaxBlockedIp::query()->create([
        'ip_address' => '203.0.113.77',
        'reason' => 'Snapshot check block',
        'is_active' => true,
    ]);
});

afterEach(function () use (&$backupTempDir) {
    DB::purge('pasax_sqlite');
    PasaxTableResolver::clearCache();
    config()->set('pasax.database.connection', 'testing');

    if ($backupTempDir !== '' && File::isDirectory($backupTempDir)) {
        File::deleteDirectory($backupTempDir);
    }
});

test('pasax:backup creates atomic sqlite snapshot with seeded rows, supports --list and --keep pruning', function () use (&$backupTempDir) {
    $this->artisan('pasax:backup')
        ->expectsOutputToContain('Backup snapshot SQLite Pasax berhasil dibuat!')
        ->assertSuccessful();

    $backups = PasaxDatabase::listBackups();
    expect($backups)->toHaveCount(1)
        ->and($backups[0]['filename'])->toStartWith('pasax-roby-')
        ->and($backups[0]['filename'])->toEndWith('.sqlite');

    $backupPath = $backups[0]['path'];
    expect(substr((string) File::get($backupPath), 0, 15))->toBe('SQLite format 3');

    // Open snapshot independently via raw PDO to verify data integrity
    $pdo = new PDO('sqlite:'.$backupPath);
    $logCount = (int) $pdo->query('SELECT COUNT(*) FROM pasax_logs')->fetchColumn();
    $blockedIp = (string) $pdo->query('SELECT ip_address FROM pasax_blocked_ips LIMIT 1')->fetchColumn();

    expect($logCount)->toBe(1)
        ->and($blockedIp)->toBe('203.0.113.77');

    // Create 2 more backups directly so total = 3, then prune with --keep=2
    PasaxDatabase::createBackup('roby', $backupTempDir.'/pasax/backups/pasax-roby-2026-01-01-000001.sqlite');
    touch($backupTempDir.'/pasax/backups/pasax-roby-2026-01-01-000001.sqlite', time() - 120);

    PasaxDatabase::createBackup('roby', $backupTempDir.'/pasax/backups/pasax-roby-2026-01-01-000002.sqlite');
    touch($backupTempDir.'/pasax/backups/pasax-roby-2026-01-01-000002.sqlite', time() - 60);

    expect(PasaxDatabase::listBackups())->toHaveCount(3);

    $this->artisan('pasax:backup', ['--keep' => 2])
        ->assertSuccessful();

    expect(PasaxDatabase::listBackups())->toHaveCount(2);

    $this->artisan('pasax:backup', ['--list' => true])
        ->expectsOutputToContain('pasax-roby-')
        ->assertSuccessful();
});

test('authenticated dashboard user can create and download sqlite backup and path traversal is rejected', function () {
    require __DIR__.'/../../routes/pasax-web-blade.php';
    Route::getRoutes()->refreshNameLookups();

    $createResp = $this->withSession([
        'pasax_dashboard_authenticated' => true,
        'pasax_dashboard_user' => 'roby',
    ])->postJson(route('pasax.dashboard.server.backup'));

    $createResp->assertOk()
        ->assertJsonPath('success', true)
        ->assertJsonStructure(['data' => ['filename', 'size_bytes', 'sha256', 'method']]);

    $filename = (string) $createResp->json('data.filename');

    $downloadResp = $this->withSession([
        'pasax_dashboard_authenticated' => true,
    ])->get(route('pasax.dashboard.server.backup.download', ['file' => $filename]));

    $downloadResp->assertOk()
        ->assertHeader('content-type', 'application/x-sqlite3')
        ->assertHeader('x-content-type-options', 'nosniff');

    $downloadedPath = $downloadResp->getFile()->getPathname();
    expect(substr((string) File::get($downloadedPath), 0, 15))->toBe('SQLite format 3');

    // Path traversal rejection
    $this->withSession(['pasax_dashboard_authenticated' => true])
        ->get(route('pasax.dashboard.server.backup.download', ['file' => '../../etc/passwd']))
        ->assertStatus(403);

    $this->withSession(['pasax_dashboard_authenticated' => true])
        ->get(route('pasax.dashboard.server.backup.download', ['file' => '../pasax.sqlite']))
        ->assertStatus(403);
});
