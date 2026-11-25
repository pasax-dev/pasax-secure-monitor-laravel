<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Pasax\SecureMonitor\Support\PasaxDatabase;

return new class extends Migration
{
    public function getConnection(): ?string
    {
        return PasaxDatabase::prepareForMigration();
    }

    public function up(): void
    {
        $connName = $this->getConnection();
        $schema = Schema::connection($connName);
        $table = config('pasax.table_names.allowed_ips', 'pasax_allowed_ips');
        $usersTable = (string) config('pasax.table_names.users', 'users');
        $hasUsersTable = PasaxDatabase::hasForeignUsersTable(
            $connName,
            $usersTable,
        );

        if ($schema->hasTable('allowed_ips') && ! $schema->hasTable($table)) {
            $schema->rename('allowed_ips', $table);
        }

        if (! $schema->hasTable($table)) {
            $schema->create($table, function (Blueprint $blueprint) use (
                $usersTable,
                $hasUsersTable,
            ) {
                $blueprint->id();
                $blueprint->string('ip_address', 45)->index();
                $blueprint->string('label', 150)->nullable();
                $blueprint->text('notes')->nullable();
                if ($hasUsersTable) {
                    $blueprint
                        ->foreignId('allowed_by')
                        ->nullable()
                        ->constrained($usersTable)
                        ->nullOnDelete();
                } else {
                    $blueprint
                        ->unsignedBigInteger('allowed_by')
                        ->nullable()
                        ->index();
                }
                $blueprint->boolean('is_active')->default(true);
                $blueprint->timestamp('expires_at')->nullable()->index();
                $blueprint->timestamps();

                $blueprint->index(['is_active', 'ip_address']);
            });
        }
    }

    public function down(): void
    {
        $schema = Schema::connection($this->getConnection());
        $schema->dropIfExists(
            config('pasax.table_names.allowed_ips', 'pasax_allowed_ips'),
        );
        $schema->dropIfExists('allowed_ips');
    }
};
