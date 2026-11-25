<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;
use Pasax\SecureMonitor\Concerns\ResolvesPasaxTable;
use Pasax\SecureMonitor\Support\PasaxDatabase;

return new class extends Migration
{
    public function getConnection(): ?string
    {
        return PasaxDatabase::prepareForMigration();
    }

    /**
     * Map of legacy un-prefixed table names to their prefixed counterpart.
     *
     * @return array<string, string>
     */
    protected function tableMap(): array
    {
        return [
            'blocked_ips' => config(
                'pasax.table_names.blocked_ips',
                'pasax_blocked_ips',
            ),
            'login_attempts' => config(
                'pasax.table_names.login_attempts',
                'pasax_login_attempts',
            ),
            'ip_unblock_requests' => config(
                'pasax.table_names.ip_unblock_requests',
                'pasax_ip_unblock_requests',
            ),
            'user_logins' => config(
                'pasax.table_names.user_logins',
                'pasax_user_logins',
            ),
            'trusted_ips' => config(
                'pasax.table_names.trusted_ips',
                'pasax_trusted_ips',
            ),
            'allowed_ips' => config(
                'pasax.table_names.allowed_ips',
                'pasax_allowed_ips',
            ),
            'security_logs' => config(
                'pasax.table_names.pasax_logs',
                'pasax_logs',
            ),
            'security_settings' => config(
                'pasax.table_names.settings',
                'pasax_settings',
            ),
        ];
    }

    public function up(): void
    {
        $connName = $this->getConnection();
        $schema =
            $connName !== null
                ? Schema::connection($connName)
                : Schema::connection(null);

        $schema->disableForeignKeyConstraints();
        try {
            foreach ($this->tableMap() as $legacy => $current) {
                if (
                    $legacy !== $current &&
                    $schema->hasTable($legacy) &&
                    ! $schema->hasTable($current)
                ) {
                    $schema->rename($legacy, $current);
                }
            }
        } finally {
            $schema->enableForeignKeyConstraints();
        }

        ResolvesPasaxTable::clearResolvedTableCache();
    }

    public function down(): void
    {
        $connName = $this->getConnection();
        $schema =
            $connName !== null
                ? Schema::connection($connName)
                : Schema::connection(null);

        $schema->disableForeignKeyConstraints();
        try {
            foreach ($this->tableMap() as $legacy => $current) {
                if (
                    $legacy !== $current &&
                    $schema->hasTable($current) &&
                    ! $schema->hasTable($legacy)
                ) {
                    $schema->rename($current, $legacy);
                }
            }
        } finally {
            $schema->enableForeignKeyConstraints();
        }

        ResolvesPasaxTable::clearResolvedTableCache();
    }
};
