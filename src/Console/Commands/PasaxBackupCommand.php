<?php

namespace Pasax\SecureMonitor\Console\Commands;

use Illuminate\Console\Command;
use Pasax\SecureMonitor\Support\PasaxDatabase;
use Throwable;

class PasaxBackupCommand extends Command
{
    protected $signature = 'pasax:backup
                            {--output= : Lokasi berkas atau direktori output snapshot .sqlite}
                            {--keep=10 : Jumlah berkas backup terbaru yang dipertahankan (0 = simpan semua)}
                            {--list : Tampilkan daftar berkas backup SQLite yang tersedia tanpa membuat snapshot baru}';

    protected $description = 'Buat snapshot backup atomik dari database SQLite terisolasi Pasax (menggunakan VACUUM INTO)';

    public function handle(): int
    {
        if ((bool) $this->option('list')) {
            return $this->renderList();
        }

        $status = PasaxDatabase::sqliteStatus();

        if (! $status['is_sqlite']) {
            $this->error("Perintah pasax:backup membutuhkan koneksi SQLite (saat ini: {$status['connection']} / {$status['driver']}).");
            $this->line('  Setel PASAX_DB_CONNECTION=pasax_sqlite pada .env untuk mengaktifkan database terisolasi.');

            return self::FAILURE;
        }

        try {
            $output = $this->option('output');
            $result = PasaxDatabase::createBackup(
                PasaxDatabase::ownerIdentifier(),
                is_string($output) && trim($output) !== '' ? trim($output) : null
            );

            $keep = max(0, (int) $this->option('keep'));
            $pruned = ($output === null || trim((string) $output) === '') && $keep > 0
                ? PasaxDatabase::pruneBackups($keep)
                : 0;

            $this->newLine();
            $this->info('  ✓ Backup snapshot SQLite Pasax berhasil dibuat!');
            $this->line('  Berkas  : <fg=cyan>'.PasaxDatabase::toRelativePath($result['path']).'</>');
            $this->line('  Akun    : <fg=white>'.$result['account'].'</>');
            $this->line('  Ukuran  : <fg=white>'.$result['size_human'].'</>');
            $this->line('  Metode  : <fg=white>'.$result['method'].'</>');
            if ($result['sha256'] !== '') {
                $this->line('  SHA-256 : <fg=gray>'.$result['sha256'].'</>');
            }
            if ($pruned > 0) {
                $this->line("  Retensi : <fg=gray>{$pruned} snapshot lama dibersihkan (keep={$keep})</>");
            }
            $this->newLine();

            return self::SUCCESS;
        } catch (Throwable $e) {
            $this->error('  ✗ Gagal membuat backup SQLite: '.$e->getMessage());

            return self::FAILURE;
        }
    }

    protected function renderList(): int
    {
        $status = PasaxDatabase::sqliteStatus();
        $backups = PasaxDatabase::listBackups();

        $this->newLine();
        $this->line('  <fg=cyan;options=bold>Status Database SQLite Pasax</>');
        $this->line('  Koneksi     : <fg=white>'.$status['connection'].' ('.$status['driver'].')</>');
        $this->line('  Lokasi DB   : <fg=white>'.$status['relative_path'].'</>');
        $this->line('  Mode WAL    : <fg=white>'.$status['journal_mode'].'</>');
        $this->line('  Dir Backup  : <fg=white>'.$status['relative_backup_dir'].'</>');
        $this->line('  Akun Terikat: <fg=white>'.$status['owner_identifier'].'</>');
        $this->newLine();

        if ($backups === []) {
            $this->line('  Belum ada snapshot backup tersimpan.');
            $this->newLine();

            return self::SUCCESS;
        }

        $this->table(
            ['Nama Berkas', 'Ukuran', 'Waktu Dibuat'],
            array_map(fn (array $b): array => [
                $b['filename'],
                $b['size_human'],
                $b['modified_at'],
            ], $backups)
        );
        $this->newLine();

        return self::SUCCESS;
    }
}
