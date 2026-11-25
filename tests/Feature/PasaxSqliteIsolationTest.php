<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
use Pasax\SecureMonitor\Models\PasaxBlockedIp;
use Pasax\SecureMonitor\Models\PasaxLog;
use Pasax\SecureMonitor\Models\PasaxSetting;
use Pasax\SecureMonitor\Services\PasaxServerSecurityService;
use Pasax\SecureMonitor\Support\PasaxDatabase;
use Pasax\SecureMonitor\Support\PasaxTableResolver;
use Pasax\SecureMonitor\Tests\TestUser;

$isoTempDir = '';

beforeEach(function () use (&$isoTempDir) {
    $isoTempDir = sys_get_temp_dir().'/pasax_sqlite_iso_'.uniqid();
    File::makeDirectory($isoTempDir, 0755, true, true);
    DB::purge('pasax_sqlite');
    DB::purge('host_sqlite');
    PasaxTableResolver::clearCache();
});

afterEach(function () use (&$isoTempDir) {
    DB::purge('pasax_sqlite');
    DB::purge('host_sqlite');
    PasaxTableResolver::clearCache();
    config()->set('database.default', 'testing');
    config()->set('pasax.database.connection', 'testing');

    if ($isoTempDir !== '' && File::isDirectory($isoTempDir)) {
        File::deleteDirectory($isoTempDir);
    }
});

test('pasax database ensureStorageReady creates directory, gitignore, backup dir, and sqlite file outside public_path', function () use (&$isoTempDir) {
    $sqlitePath = $isoTempDir.'/pasax/pasax.sqlite';
    $backupDir = $isoTempDir.'/pasax/backups';

    config()->set('pasax.database.connection', 'pasax_sqlite');
    config()->set('pasax.database.path', $sqlitePath);
    config()->set('pasax.database.backup_path', $backupDir);

    $prep = PasaxDatabase::ensureStorageReady();

    expect(File::isDirectory($prep['directory']))->toBeTrue()
        ->and(File::isDirectory($prep['backup_directory']))->toBeTrue()
        ->and(File::exists($prep['sqlite_path']))->toBeTrue()
        ->and(File::exists($prep['gitignore_path']))->toBeTrue()
        ->and(str_starts_with($prep['sqlite_path'], public_path()))->toBeFalse();

    $gitignore = File::get($prep['gitignore_path']);
    expect($gitignore)
        ->toContain('*.sqlite*')
        ->toContain('*.db*')
        ->toContain('backups/')
        ->toContain('!.gitignore');
});

test('pasax migrations and models run in isolated pasax_sqlite database while host tables stay on separate host connection and cross-db relations work', function () use (&$isoTempDir) {
    $hostSqlite = $isoTempDir.'/host.sqlite';
    $pasaxSqlite = $isoTempDir.'/pasax/pasax.sqlite';
    $backupDir = $isoTempDir.'/pasax/backups';

    File::put($hostSqlite, '');

    config()->set('database.default', 'host_sqlite');
    config()->set('database.connections.host_sqlite', [
        'driver' => 'sqlite',
        'database' => $hostSqlite,
        'prefix' => '',
        'foreign_key_constraints' => true,
    ]);

    Schema::connection('host_sqlite')->create('users', function (Blueprint $table) {
        $table->id();
        $table->string('name');
        $table->string('email')->unique();
        $table->string('password');
        $table->string('role')->default('user');
        $table->timestamp('two_factor_confirmed_at')->nullable();
        $table->timestamps();
    });

    config()->set('pasax.database.connection', 'pasax_sqlite');
    config()->set('pasax.database.path', $pasaxSqlite);
    config()->set('pasax.database.backup_path', $backupDir);
    config()->set('pasax.database.sqlite_wal', true);

    PasaxDatabase::prepareForMigration();

    $this->artisan('migrate', [
        '--database' => 'pasax_sqlite',
        '--path' => realpath(__DIR__.'/../../database/migrations'),
        '--realpath' => true,
        '--force' => true,
    ])->assertSuccessful();

    // Host DB stays clean (no Pasax tables leaked into host DB)
    expect(Schema::connection('host_sqlite')->hasTable('users'))->toBeTrue()
        ->and(Schema::connection('host_sqlite')->hasTable('pasax_logs'))->toBeFalse()
        ->and(Schema::connection('host_sqlite')->hasTable('pasax_blocked_ips'))->toBeFalse()
        ->and(Schema::connection('host_sqlite')->hasTable('pasax_settings'))->toBeFalse();

    // Isolated Pasax SQLite contains Pasax tables (and not host users table)
    expect(PasaxDatabase::schema()->hasTable('pasax_logs'))->toBeTrue()
        ->and(PasaxDatabase::schema()->hasTable('pasax_blocked_ips'))->toBeTrue()
        ->and(PasaxDatabase::schema()->hasTable('pasax_settings'))->toBeTrue()
        ->and(PasaxDatabase::schema()->hasTable('users'))->toBeFalse();

    // WAL mode & foreign_keys PRAGMA applied
    $walRow = (array) PasaxDatabase::connection()->selectOne('PRAGMA journal_mode');
    $fkRow = (array) PasaxDatabase::connection()->selectOne('PRAGMA foreign_keys');
    expect(strtolower((string) reset($walRow)))->toBe('wal')
        ->and((int) reset($fkRow))->toBe(1);

    // Create host user on host_sqlite and Pasax records on pasax_sqlite
    $hostUser = TestUser::create([
        'name' => 'Host Owner',
        'email' => 'host-owner@example.com',
        'password' => bcrypt('secret'),
        'role' => 'admin',
    ]);

    $log = PasaxLog::query()->create([
        'user_id' => $hostUser->id,
        'ip_address' => '198.51.100.25',
        'event_type' => 'xss',
        'threat_level' => 'high',
        'path' => '/search',
        'full_url' => 'https://example.test/search?q=<script>',
        'method' => 'GET',
        'evidence' => 'Isolated SQLite test',
    ]);

    PasaxBlockedIp::query()->create([
        'ip_address' => '198.51.100.25',
        'reason' => 'Automated XSS probe',
        'blocked_by' => $hostUser->id,
        'is_active' => true,
    ]);

    PasaxSetting::query()->updateOrCreate(['key' => 'test_isolation'], ['value' => 'yes']);

    expect(DB::connection('pasax_sqlite')->table('pasax_logs')->count())->toBe(1)
        ->and(DB::connection('pasax_sqlite')->table('pasax_blocked_ips')->count())->toBe(1)
        ->and(DB::connection('pasax_sqlite')->table('pasax_settings')->where('key', 'test_isolation')->value('value'))->toBe('yes');

    // Cross-DB Eloquent relationship resolves host User cleanly
    /** @var PasaxLog|null $loaded */
    $loaded = PasaxLog::query()->with('user')->find($log->id);
    expect($loaded)->not->toBeNull();
    /** @var TestUser|null $loadedUser */
    $loadedUser = $loaded?->getRelationValue('user');
    expect($loadedUser)->not->toBeNull()
        ->and($loadedUser?->email)->toBe('host-owner@example.com');

    // Server audit reports pasax_database & pasax_sqlite_wal checks cleanly
    $audit = app(PasaxServerSecurityService::class);
    $audit->forget();
    $scan = $audit->scan(true);
    $dbCheckIds = collect($scan['categories'] ?? [])->flatMap(fn (array $cat): array => array_column($cat['checks'] ?? [], 'id'))->all();
    expect($dbCheckIds)->toContain('pasax_database')
        ->toContain('pasax_sqlite_wal');
});
