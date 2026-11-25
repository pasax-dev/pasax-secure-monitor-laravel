<?php

namespace Pasax\SecureMonitor\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use RuntimeException;
use Throwable;

/**
 * Pengelola koneksi database terisolasi untuk Pasax (`pasax_sqlite` secara bawaan).
 *
 * Memisahkan tabel keamanan Pasax (logs, blocked IPs, attempts, tickets, settings)
 * ke berkas SQLite khusus di luar webroot (`storage/app/pasax/pasax.sqlite`)
 * sambil tetap mendukung fallback koneksi host (`mysql`/`pgsql`/`testing`)
 * atau mode database gabungan bila dikonfigurasi oleh pengguna.
 */
class PasaxDatabase
{
    public const DEFAULT_CONNECTION = 'pasax_sqlite';

    public const DEFAULT_RELATIVE_PATH = 'storage/app/pasax/pasax.sqlite';

    public const DEFAULT_RELATIVE_BACKUP_DIR = 'storage/app/pasax/backups';

    /**
     * Lacak PDO yang sudah menerapkan PRAGMA WAL/busy_timeout agar tidak diulang.
     *
     * @var array<int, true>
     */
    protected static array $initializedPdos = [];

    /**
     * Nama koneksi database yang digunakan seluruh model & migrasi Pasax.
     * Mengembalikan null jika memakai koneksi default aplikasi host.
     */
    public static function connectionName(): ?string
    {
        try {
            $configured = config(
                'pasax.database.connection',
                self::DEFAULT_CONNECTION,
            );
        } catch (Throwable) {
            $configured = self::DEFAULT_CONNECTION;
        }

        if (! is_string($configured)) {
            return null;
        }

        $trimmed = trim($configured);

        if ($trimmed === '' || $trimmed === 'default') {
            return null;
        }

        // Saat unit/feature test aplikasi host memakai `:memory:` (mis. phpunit.xml standar
        // dengan DB_DATABASE=:memory: dan RefreshDatabase) tanpa override `pasax.database.path`,
        // ikuti koneksi `:memory:` default agar migrasi & transaksi RefreshDatabase sinkron
        // serta tidak mencemari berkas SQLite produksi di disk.
        if ($trimmed === self::DEFAULT_CONNECTION) {
            try {
                if (app()->runningUnitTests()) {
                    $defaultConn = (string) config('database.default', '');
                    $defaultDriver = (string) config(
                        "database.connections.{$defaultConn}.driver",
                        '',
                    );
                    $defaultDb = (string) config(
                        "database.connections.{$defaultConn}.database",
                        '',
                    );

                    if (
                        $defaultDriver === 'sqlite' &&
                        $defaultDb === ':memory:'
                    ) {
                        $configuredPath = self::sqlitePath();
                        $defaultPath = storage_path('app/pasax/pasax.sqlite');

                        if ($configuredPath === $defaultPath) {
                            return null;
                        }
                    }
                }
            } catch (Throwable) {
            }
        }

        return $trimmed;
    }

    /**
     * Periksa apakah Pasax menggunakan koneksi database yang terpisah dari host.
     */
    public static function isSeparateConnection(): bool
    {
        $pasaxConn = self::connectionName();

        if ($pasaxConn === null) {
            return false;
        }

        try {
            $defaultConn = (string) config('database.default', '');
        } catch (Throwable) {
            return true;
        }

        return $pasaxConn !== $defaultConn;
    }

    /**
     * Periksa apakah koneksi Pasax memakai driver SQLite.
     */
    public static function isSqlite(?string $connection = null): bool
    {
        $conn = $connection ?? self::connectionName();

        if ($conn === null) {
            try {
                $conn = (string) config('database.default', '');
            } catch (Throwable) {
                return false;
            }
        }

        if ($conn === self::DEFAULT_CONNECTION) {
            return true;
        }

        try {
            $driver = (string) config(
                "database.connections.{$conn}.driver",
                '',
            );

            return $driver === 'sqlite';
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Dapatkan path absolut berkas SQLite Pasax.
     */
    public static function sqlitePath(): string
    {
        try {
            $configured = config('pasax.database.path');
        } catch (Throwable) {
            $configured = null;
        }

        if (is_string($configured) && trim($configured) !== '') {
            return self::resolvePath(trim($configured));
        }

        return storage_path('app/pasax/pasax.sqlite');
    }

    /**
     * Dapatkan path absolut direktori penyimpanan backup SQLite Pasax.
     */
    public static function backupDirectory(): string
    {
        try {
            $configured = config('pasax.database.backup_path');
        } catch (Throwable) {
            $configured = null;
        }

        if (is_string($configured) && trim($configured) !== '') {
            return self::resolvePath(trim($configured));
        }

        return storage_path('app/pasax/backups');
    }

    /**
     * Daftarkan definisi koneksi `pasax_sqlite` ke runtime `config/database.php`.
     */
    public static function configureConnection(
        ?string $overridePath = null,
    ): void {
        if ($overridePath !== null && trim($overridePath) !== '') {
            config()->set('pasax.database.path', trim($overridePath));
        }

        $connName = self::connectionName();
        if ($connName === null) {
            return;
        }

        if ($connName === self::DEFAULT_CONNECTION) {
            $sqlitePath = self::sqlitePath();
            $wal = (bool) config('pasax.database.sqlite_wal', true);
            $busyTimeout = max(
                1000,
                (int) config('pasax.database.sqlite_busy_timeout', 5000),
            );

            $existing = config("database.connections.{$connName}");
            $definition = [
                'driver' => 'sqlite',
                'url' => null,
                'database' => $sqlitePath,
                'prefix' => is_array($existing)
                    ? (string) ($existing['prefix'] ?? '')
                    : '',
                'foreign_key_constraints' => true,
                'busy_timeout' => $busyTimeout,
                'journal_mode' => $wal ? 'WAL' : null,
                'synchronous' => $wal ? 'NORMAL' : null,
            ];

            config()->set("database.connections.{$connName}", $definition);
        }
    }

    /**
     * Pastikan direktori `storage/app/pasax`, `backups`, `.gitignore`, dan berkas SQLite siap digunakan.
     *
     * @return array{directory: string, backup_directory: string, sqlite_path: string, created_file: bool, gitignore_path: string}
     */
    public static function ensureStorageReady(
        ?string $sqlitePath = null,
        ?string $backupDir = null,
    ): array {
        $resolvedSqlite =
            $sqlitePath !== null
                ? self::resolvePath($sqlitePath)
                : self::sqlitePath();
        $resolvedBackupDir =
            $backupDir !== null
                ? self::resolvePath($backupDir)
                : self::backupDirectory();
        $baseDir =
            $resolvedSqlite !== ':memory:'
                ? dirname($resolvedSqlite)
                : storage_path('app/pasax');

        if (! File::isDirectory($baseDir)) {
            File::makeDirectory($baseDir, 0750, true, true);
        }
        @chmod($baseDir, 0750);

        if (! File::isDirectory($resolvedBackupDir)) {
            File::makeDirectory($resolvedBackupDir, 0750, true, true);
        }
        @chmod($resolvedBackupDir, 0750);

        $gitignorePath = $baseDir.DIRECTORY_SEPARATOR.'.gitignore';
        $gitignoreContent = "*.sqlite*\n*.db*\nbackups/\n!.gitignore\n";
        if (
            ! File::exists($gitignorePath) ||
            File::get($gitignorePath) !== $gitignoreContent
        ) {
            File::put($gitignorePath, $gitignoreContent);
        }

        $createdFile = false;
        if ($resolvedSqlite !== ':memory:' && ! File::exists($resolvedSqlite)) {
            File::put($resolvedSqlite, '');
            @chmod($resolvedSqlite, 0640);
            $createdFile = true;
        } elseif (
            $resolvedSqlite !== ':memory:' &&
            File::exists($resolvedSqlite)
        ) {
            @chmod($resolvedSqlite, 0640);
        }

        return [
            'directory' => $baseDir,
            'backup_directory' => $resolvedBackupDir,
            'sqlite_path' => $resolvedSqlite,
            'created_file' => $createdFile,
            'gitignore_path' => $gitignorePath,
        ];
    }

    /**
     * Persiapkan koneksi & file SQLite sebelum menjalankan migrasi Pasax.
     */
    public static function prepareForMigration(): ?string
    {
        self::configureConnection();

        $connName = self::connectionName();
        if (self::isSqlite($connName)) {
            $path = self::sqlitePath();
            if ($path !== ':memory:') {
                self::ensureStorageReady($path);
            }
        }

        return $connName;
    }

    /**
     * Pastikan skema database terisolasi (`pasax_sqlite`) sudah termigrasi meskipun
     * tabel `migrations` pada DB host sudah mencatat migrasi Pasax dari versi lama.
     * Secara opsional menyalin data lama dari DB host bila SQLite terisolasi masih kosong.
     *
     * @return array{migrated: bool, copied_rows: int, connection: ?string}
     */
    public static function ensureIsolatedSchemaReady(
        bool $migrateHostDataIfEmpty = false,
    ): array {
        $connName = self::prepareForMigration();
        if ($connName === null || ! self::isSeparateConnection()) {
            return [
                'migrated' => false,
                'copied_rows' => 0,
                'connection' => $connName,
            ];
        }

        $targetSchema = self::schema();
        $logsTable = (string) config(
            'pasax.table_names.pasax_logs',
            'pasax_logs',
        );
        $blockedTable = (string) config(
            'pasax.table_names.blocked_ips',
            'pasax_blocked_ips',
        );
        $settingsTable = (string) config(
            'pasax.table_names.settings',
            'pasax_settings',
        );

        $schemaComplete =
            $targetSchema->hasTable($logsTable) &&
            $targetSchema->hasTable($blockedTable) &&
            $targetSchema->hasTable($settingsTable);

        $migrated = false;
        if (! $schemaComplete) {
            $migrationsPath = dirname(__DIR__, 2).'/database/migrations';
            if (File::isDirectory($migrationsPath)) {
                Artisan::call('migrate', [
                    '--database' => $connName,
                    '--path' => $migrationsPath,
                    '--realpath' => true,
                    '--force' => true,
                ]);
                $migrated = true;
            }
        }

        $copiedRows = 0;
        if ($migrateHostDataIfEmpty) {
            $copiedRows = self::migrateLegacyHostDataToIsolatedConnection(
                $connName,
            );
        }

        return [
            'migrated' => $migrated,
            'copied_rows' => $copiedRows,
            'connection' => $connName,
        ];
    }

    /**
     * Salin data Pasax lama dari koneksi default host ke koneksi terisolasi jika
     * tabel target masih kosong agar proses upgrade ke SQLite tidak kehilangan data.
     */
    protected static function migrateLegacyHostDataToIsolatedConnection(
        string $targetConnName,
    ): int {
        try {
            $hostConnName = (string) config('database.default', '');
            if ($hostConnName === '' || $hostConnName === $targetConnName) {
                return 0;
            }

            $hostSchema = Schema::connection($hostConnName);
            $targetSchema = Schema::connection($targetConnName);
            $hostDb = DB::connection($hostConnName);
            $targetDb = DB::connection($targetConnName);

            $tables = array_values(
                array_unique([
                    (string) config(
                        'pasax.table_names.settings',
                        'pasax_settings',
                    ),
                    (string) config(
                        'pasax.table_names.blocked_ips',
                        'pasax_blocked_ips',
                    ),
                    (string) config(
                        'pasax.table_names.allowed_ips',
                        'pasax_allowed_ips',
                    ),
                    (string) config(
                        'pasax.table_names.trusted_ips',
                        'pasax_trusted_ips',
                    ),
                    (string) config(
                        'pasax.table_names.ip_unblock_requests',
                        'pasax_ip_unblock_requests',
                    ),
                    (string) config(
                        'pasax.table_names.login_attempts',
                        'pasax_login_attempts',
                    ),
                    (string) config(
                        'pasax.table_names.user_logins',
                        'pasax_user_logins',
                    ),
                    (string) config(
                        'pasax.table_names.pasax_logs',
                        'pasax_logs',
                    ),
                ]),
            );

            $totalCopied = 0;
            $targetSchema->disableForeignKeyConstraints();

            try {
                foreach ($tables as $table) {
                    if (
                        $table === '' ||
                        ! $hostSchema->hasTable($table) ||
                        ! $targetSchema->hasTable($table)
                    ) {
                        continue;
                    }

                    if ($targetDb->table($table)->count() > 0) {
                        continue;
                    }

                    $sourceCount = $hostDb->table($table)->count();
                    if ($sourceCount === 0) {
                        continue;
                    }

                    $targetColumns = array_flip(
                        $targetSchema->getColumnListing($table),
                    );
                    $batch = [];

                    foreach ($hostDb->table($table)->cursor() as $row) {
                        $filtered = array_intersect_key(
                            (array) $row,
                            $targetColumns,
                        );
                        if ($filtered !== []) {
                            $batch[] = $filtered;
                        }

                        if (count($batch) >= 200) {
                            $targetDb->table($table)->insert($batch);
                            $totalCopied += count($batch);
                            $batch = [];
                        }
                    }

                    if ($batch !== []) {
                        $targetDb->table($table)->insert($batch);
                        $totalCopied += count($batch);
                    }
                }
            } finally {
                $targetSchema->enableForeignKeyConstraints();
            }

            return $totalCopied;
        } catch (Throwable) {
            return 0;
        }
    }

    /**
     * Dapatkan instance koneksi database Pasax dan terapkan PRAGMA SQLite jika relevan.
     */
    public static function connection(): Connection
    {
        self::configureConnection();

        $connName = self::connectionName();

        if (self::isSqlite($connName)) {
            $path = self::sqlitePath();
            if (
                $connName === self::DEFAULT_CONNECTION &&
                $path !== ':memory:' &&
                ! is_file($path)
            ) {
                self::ensureStorageReady($path);
            }
        }

        $conn =
            $connName !== null ? DB::connection($connName) : DB::connection();

        if (
            $conn instanceof Connection &&
            $conn->getDriverName() === 'sqlite'
        ) {
            self::applySqlitePragmas($conn);
        }

        /** @var Connection $conn */
        return $conn;
    }

    /**
     * Dapatkan Schema Builder untuk koneksi database Pasax.
     */
    public static function schema(): Builder
    {
        self::connection();
        $connName = self::connectionName();

        return $connName !== null
            ? Schema::connection($connName)
            : Schema::connection(null);
    }

    /**
     * Terapkan PRAGMA performa & keamanan SQLite (WAL, synchronous NORMAL, busy_timeout, foreign_keys).
     */
    public static function applySqlitePragmas(
        ConnectionInterface $connection,
    ): void {
        if (
            ! ($connection instanceof Connection) ||
            $connection->getDriverName() !== 'sqlite'
        ) {
            return;
        }

        try {
            $pdo = $connection->getPdo();
            $pdoId = spl_object_id($pdo);

            if (isset(self::$initializedPdos[$pdoId])) {
                return;
            }

            $busyTimeout = max(
                1000,
                (int) config('pasax.database.sqlite_busy_timeout', 5000),
            );
            $wal = (bool) config('pasax.database.sqlite_wal', true);

            $pdo->exec('PRAGMA foreign_keys = ON');
            $pdo->exec("PRAGMA busy_timeout = {$busyTimeout}");

            if ($wal) {
                $pdo->exec('PRAGMA journal_mode = WAL');
                $pdo->exec('PRAGMA synchronous = NORMAL');
            }

            self::$initializedPdos[$pdoId] = true;
        } catch (Throwable) {
            // Abaikan bila PDO belum siap atau tidak mendukung pragma tertentu
        }
    }

    /**
     * Periksa apakah tabel `users` milik host berada pada koneksi yang sama dengan migrasi Pasax
     * (menghindari SQL foreign key error lintas database ketika SQLite terpisah).
     */
    public static function hasForeignUsersTable(
        ?string $connection,
        string $usersTable,
    ): bool {
        if ($usersTable === '') {
            return false;
        }

        try {
            $schema =
                $connection !== null
                    ? Schema::connection($connection)
                    : Schema::connection(null);

            return $schema->hasTable($usersTable);
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Dapatkan identifier pemilik akun untuk penamaan backup & akses terikat akun.
     */
    public static function ownerIdentifier(): string
    {
        $owner = PasaxDashboardSecret::resolveOwnerIdentity();

        $candidate =
            $owner['username'] ?:
            ($owner['email']
                ? Str::before($owner['email'], '@')
                : '') ?:
            (string) config('pasax.dashboard.auth.username', 'admin');

        return self::sanitizeAccountSlug($candidate);
    }

    /**
     * Normalisasi identifier akun agar aman dipakai pada nama berkas backup.
     */
    public static function sanitizeAccountSlug(string $account): string
    {
        $base = str_contains($account, '@')
            ? Str::before($account, '@')
            : $account;
        $slug = Str::slug($base, '-');

        return $slug !== '' ? $slug : 'admin';
    }

    /**
     * Buat backup snapshot atomik dari database SQLite Pasax.
     *
     * @return array{success: bool, path: string, filename: string, size_bytes: int, size_human: string, sha256: string, account: string, created_at: string, method: string}
     */
    public static function createBackup(
        ?string $account = null,
        ?string $outputPath = null,
    ): array {
        if (! self::isSqlite()) {
            throw new RuntimeException(
                'Snapshot SQLite otomatis hanya tersedia saat PASAX_DB_CONNECTION menggunakan driver SQLite (saat ini: '.
                    (self::connectionName() ?? 'default').
                    ').',
            );
        }

        $storage = self::ensureStorageReady();
        $accountSlug = self::sanitizeAccountSlug(
            $account ?? self::ownerIdentifier(),
        );
        $timestamp = now()->format('Y-m-d-His');

        if ($outputPath !== null && trim($outputPath) !== '') {
            $targetPath = self::resolvePath(trim($outputPath));
            if (is_dir($targetPath)) {
                $targetPath =
                    rtrim($targetPath, DIRECTORY_SEPARATOR).
                    DIRECTORY_SEPARATOR.
                    "pasax-{$accountSlug}-{$timestamp}.sqlite";
            }
            $parentDir = dirname($targetPath);
            if (! File::isDirectory($parentDir)) {
                File::makeDirectory($parentDir, 0750, true, true);
            }
            if (File::exists($targetPath)) {
                File::delete($targetPath);
            }
        } else {
            $backupDir = $storage['backup_directory'];
            $targetPath =
                $backupDir.
                DIRECTORY_SEPARATOR.
                "pasax-{$accountSlug}-{$timestamp}.sqlite";
            if (File::exists($targetPath)) {
                $suffix = substr(bin2hex(random_bytes(2)), 0, 4);
                $targetPath =
                    $backupDir.
                    DIRECTORY_SEPARATOR.
                    "pasax-{$accountSlug}-{$timestamp}-{$suffix}.sqlite";
            }
        }

        $conn = self::connection();
        $pdo = $conn->getPdo();
        $method = 'vacuum_into';

        try {
            $pdo->exec('VACUUM INTO '.$pdo->quote($targetPath));
        } catch (Throwable $vacuumError) {
            $sourcePath = self::sqlitePath();
            if ($sourcePath === ':memory:' || ! File::exists($sourcePath)) {
                throw new RuntimeException(
                    'Gagal membuat backup SQLite: '.
                        $vacuumError->getMessage(),
                    0,
                    $vacuumError,
                );
            }

            $method = 'wal_checkpoint_copy';
            try {
                $pdo->exec('PRAGMA wal_checkpoint(TRUNCATE)');
            } catch (Throwable) {
                // Lanjutkan penyalinan berkas
            }

            if (! File::copy($sourcePath, $targetPath)) {
                throw new RuntimeException(
                    'Gagal menyalin berkas SQLite ke '.$targetPath,
                );
            }
        }

        @chmod($targetPath, 0640);
        clearstatcache(true, $targetPath);

        $size = File::exists($targetPath) ? (int) File::size($targetPath) : 0;
        $sha256 = File::exists($targetPath)
            ? (string) hash_file('sha256', $targetPath)
            : '';

        return [
            'success' => true,
            'path' => $targetPath,
            'filename' => basename($targetPath),
            'size_bytes' => $size,
            'size_human' => self::formatBytes($size),
            'sha256' => $sha256,
            'account' => $accountSlug,
            'created_at' => now()->toIso8601String(),
            'method' => $method,
        ];
    }

    /**
     * Daftar berkas backup SQLite yang tersimpan di direktori backup.
     *
     * @return array<int, array{filename: string, path: string, size_bytes: int, size_human: string, modified_at: string, timestamp: int}>
     */
    public static function listBackups(): array
    {
        $dir = self::backupDirectory();
        if (! File::isDirectory($dir)) {
            return [];
        }

        $files = glob($dir.DIRECTORY_SEPARATOR.'*.sqlite') ?: [];
        $items = [];

        foreach ($files as $file) {
            if (! is_file($file)) {
                continue;
            }
            $mtime = (int) filemtime($file);
            $size = (int) filesize($file);
            $items[] = [
                'filename' => basename($file),
                'path' => $file,
                'size_bytes' => $size,
                'size_human' => self::formatBytes($size),
                'modified_at' => date('Y-m-d H:i:s', $mtime),
                'timestamp' => $mtime,
            ];
        }

        usort(
            $items,
            static fn (array $a, array $b): int => $b['timestamp'] <=>
                $a['timestamp'],
        );

        return $items;
    }

    /**
     * Hapus backup lama sehingga hanya menyisakan N berkas terbaru.
     */
    public static function pruneBackups(int $keep = 10): int
    {
        if ($keep <= 0) {
            return 0;
        }

        $backups = self::listBackups();
        if (count($backups) <= $keep) {
            return 0;
        }

        $toDelete = array_slice($backups, $keep);
        $deleted = 0;

        foreach ($toDelete as $item) {
            if (File::exists($item['path']) && File::delete($item['path'])) {
                $deleted++;
            }
        }

        return $deleted;
    }

    /**
     * Ringkasan status database SQLite terisolasi Pasax untuk panel Server Audit & CLI.
     *
     * @return array{
     *   connection: string,
     *   driver: string,
     *   is_sqlite: bool,
     *   is_isolated: bool,
     *   path: string,
     *   relative_path: string,
     *   exists: bool,
     *   writable: bool,
     *   size_bytes: int,
     *   size_human: string,
     *   journal_mode: string,
     *   wal_enabled: bool,
     *   backup_dir: string,
     *   relative_backup_dir: string,
     *   backup_count: int,
     *   owner_identifier: string
     * }
     */
    public static function sqliteStatus(): array
    {
        self::configureConnection();
        $connName =
            self::connectionName() ??
            (string) config('database.default', 'mysql');
        $isSqlite = self::isSqlite($connName);
        $driver = $isSqlite
            ? 'sqlite'
            : (string) config(
                "database.connections.{$connName}.driver",
                $connName,
            );
        $path = $isSqlite
            ? self::sqlitePath()
            : (string) config("database.connections.{$connName}.database", '');
        $backupDir = self::backupDirectory();
        $exists = $isSqlite && $path !== ':memory:' ? is_file($path) : false;
        $size = $exists ? (int) filesize($path) : 0;
        $walMode = 'n/a';
        $walEnabled = false;

        if ($isSqlite && ($exists || $path === ':memory:')) {
            try {
                $row = self::connection()->selectOne('PRAGMA journal_mode');
                $arr = is_object($row)
                    ? (array) $row
                    : (is_array($row)
                        ? $row
                        : []);
                $walMode = strtolower((string) reset($arr));
                $walEnabled = $walMode === 'wal';
            } catch (Throwable) {
                $walMode = 'unknown';
            }
        }

        $backups = self::listBackups();

        return [
            'connection' => $connName,
            'driver' => $driver,
            'is_sqlite' => $isSqlite,
            'is_isolated' => self::isSeparateConnection(),
            'path' => $path,
            'relative_path' => self::toRelativePath($path),
            'exists' => $exists,
            'writable' => $exists
                ? is_writable($path)
                : is_dir(dirname($path)) && is_writable(dirname($path)),
            'size_bytes' => $size,
            'size_human' => self::formatBytes($size),
            'journal_mode' => $walMode,
            'wal_enabled' => $walEnabled,
            'backup_dir' => $backupDir,
            'relative_backup_dir' => self::toRelativePath($backupDir),
            'backup_count' => count($backups),
            'owner_identifier' => self::ownerIdentifier(),
        ];
    }

    /**
     * Ubah path relatif menjadi path absolut berbasis `base_path()`.
     */
    public static function resolvePath(string $path): string
    {
        if ($path === ':memory:') {
            return $path;
        }

        if (
            str_starts_with($path, '/') ||
            preg_match('/^[A-Za-z]:[\\\\\\/]/', $path) === 1
        ) {
            return $path;
        }

        return base_path(ltrim($path, '/\\'));
    }

    public static function toRelativePath(string $path): string
    {
        $base = rtrim(base_path(), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;

        return str_starts_with($path, $base)
            ? substr($path, strlen($base))
            : $path;
    }

    public static function formatBytes(int $bytes): string
    {
        if ($bytes < 1024) {
            return $bytes.' B';
        }
        if ($bytes < 1048576) {
            return number_format($bytes / 1024, 1).' KB';
        }
        if ($bytes < 1073741824) {
            return number_format($bytes / 1048576, 2).' MB';
        }

        return number_format($bytes / 1073741824, 2).' GB';
    }
}
