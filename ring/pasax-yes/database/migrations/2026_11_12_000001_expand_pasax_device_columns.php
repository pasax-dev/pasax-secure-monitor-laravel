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

    /**
     * Run the migrations.
     */
    public function up(): void
    {
        $schema = Schema::connection($this->getConnection());
        $connection = $schema->getConnection();
        $driver = $connection->getDriverName();

        $trustedTables = array_unique([
            config('pasax.table_names.trusted_ips', 'pasax_trusted_ips'),
            'pasax_trusted_ips',
            'trusted_ips',
        ]);

        foreach ($trustedTables as $table) {
            if ($schema->hasTable($table)) {
                // SQLite tidak menerapkan batas karakter VARCHAR secara ketat
                // dan tidak memerlukan Doctrine DBAL untuk ubah kolom.
                if ($driver === 'sqlite') {
                    continue;
                }

                if ($driver === 'mysql' || $driver === 'mariadb') {
                    if ($schema->hasColumn($table, 'operating_system')) {
                        $connection->statement(
                            "ALTER TABLE `{$table}` MODIFY `operating_system` VARCHAR(255) NULL",
                        );
                    }
                    if ($schema->hasColumn($table, 'browser')) {
                        $connection->statement(
                            "ALTER TABLE `{$table}` MODIFY `browser` VARCHAR(255) NULL",
                        );
                    }

                    continue;
                }

                if ($driver === 'pgsql') {
                    if ($schema->hasColumn($table, 'operating_system')) {
                        $connection->statement(
                            "ALTER TABLE \"{$table}\" ALTER COLUMN \"operating_system\" TYPE VARCHAR(255)",
                        );
                    }
                    if ($schema->hasColumn($table, 'browser')) {
                        $connection->statement(
                            "ALTER TABLE \"{$table}\" ALTER COLUMN \"browser\" TYPE VARCHAR(255)",
                        );
                    }

                    continue;
                }

                try {
                    $schema->table($table, function (Blueprint $blueprint) use (
                        $schema,
                        $table,
                    ) {
                        if ($schema->hasColumn($table, 'operating_system')) {
                            $blueprint
                                ->string('operating_system', 255)
                                ->nullable()
                                ->change();
                        }
                        if ($schema->hasColumn($table, 'browser')) {
                            $blueprint
                                ->string('browser', 255)
                                ->nullable()
                                ->change();
                        }
                    });
                } catch (Throwable) {
                    // Abaikan jika database engine tidak mendukung change column tanpa doctrine/dbal
                }
            }
        }

        $loginTables = array_unique([
            config('pasax.table_names.user_logins', 'pasax_user_logins'),
            'pasax_user_logins',
            'user_logins',
        ]);

        foreach ($loginTables as $table) {
            if ($schema->hasTable($table)) {
                if ($driver === 'sqlite') {
                    continue;
                }

                if ($driver === 'mysql' || $driver === 'mariadb') {
                    if ($schema->hasColumn($table, 'operating_system')) {
                        $connection->statement(
                            "ALTER TABLE `{$table}` MODIFY `operating_system` VARCHAR(255) NOT NULL DEFAULT 'Unknown OS'",
                        );
                    }
                    if ($schema->hasColumn($table, 'browser')) {
                        $connection->statement(
                            "ALTER TABLE `{$table}` MODIFY `browser` VARCHAR(255) NOT NULL DEFAULT 'Unknown Browser'",
                        );
                    }

                    continue;
                }

                if ($driver === 'pgsql') {
                    if ($schema->hasColumn($table, 'operating_system')) {
                        $connection->statement(
                            "ALTER TABLE \"{$table}\" ALTER COLUMN \"operating_system\" TYPE VARCHAR(255)",
                        );
                    }
                    if ($schema->hasColumn($table, 'browser')) {
                        $connection->statement(
                            "ALTER TABLE \"{$table}\" ALTER COLUMN \"browser\" TYPE VARCHAR(255)",
                        );
                    }

                    continue;
                }

                try {
                    $schema->table($table, function (Blueprint $blueprint) use (
                        $schema,
                        $table,
                    ) {
                        if ($schema->hasColumn($table, 'operating_system')) {
                            $blueprint
                                ->string('operating_system', 255)
                                ->default('Unknown OS')
                                ->change();
                        }
                        if ($schema->hasColumn($table, 'browser')) {
                            $blueprint
                                ->string('browser', 255)
                                ->default('Unknown Browser')
                                ->change();
                        }
                    });
                } catch (Throwable) {
                    // Abaikan jika database engine tidak mendukung change column tanpa doctrine/dbal
                }
            }
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $schema = Schema::connection($this->getConnection());
        $connection = $schema->getConnection();
        $driver = $connection->getDriverName();

        $trustedTables = array_unique([
            config('pasax.table_names.trusted_ips', 'pasax_trusted_ips'),
            'pasax_trusted_ips',
            'trusted_ips',
        ]);

        foreach ($trustedTables as $table) {
            if ($schema->hasTable($table)) {
                if ($driver === 'sqlite') {
                    continue;
                }

                if ($driver === 'mysql' || $driver === 'mariadb') {
                    if ($schema->hasColumn($table, 'operating_system')) {
                        $connection->statement(
                            "ALTER TABLE `{$table}` MODIFY `operating_system` VARCHAR(100) NULL",
                        );
                    }
                    if ($schema->hasColumn($table, 'browser')) {
                        $connection->statement(
                            "ALTER TABLE `{$table}` MODIFY `browser` VARCHAR(100) NULL",
                        );
                    }

                    continue;
                }

                if ($driver === 'pgsql') {
                    if ($schema->hasColumn($table, 'operating_system')) {
                        $connection->statement(
                            "ALTER TABLE \"{$table}\" ALTER COLUMN \"operating_system\" TYPE VARCHAR(100)",
                        );
                    }
                    if ($schema->hasColumn($table, 'browser')) {
                        $connection->statement(
                            "ALTER TABLE \"{$table}\" ALTER COLUMN \"browser\" TYPE VARCHAR(100)",
                        );
                    }

                    continue;
                }

                try {
                    $schema->table($table, function (Blueprint $blueprint) use (
                        $schema,
                        $table,
                    ) {
                        if ($schema->hasColumn($table, 'operating_system')) {
                            $blueprint
                                ->string('operating_system', 100)
                                ->nullable()
                                ->change();
                        }
                        if ($schema->hasColumn($table, 'browser')) {
                            $blueprint
                                ->string('browser', 100)
                                ->nullable()
                                ->change();
                        }
                    });
                } catch (Throwable) {
                    // Abaikan jika driver tidak mendukung rollback change column
                }
            }
        }

        $loginTables = array_unique([
            config('pasax.table_names.user_logins', 'pasax_user_logins'),
            'pasax_user_logins',
            'user_logins',
        ]);

        foreach ($loginTables as $table) {
            if ($schema->hasTable($table)) {
                if ($driver === 'sqlite') {
                    continue;
                }

                if ($driver === 'mysql' || $driver === 'mariadb') {
                    if ($schema->hasColumn($table, 'operating_system')) {
                        $connection->statement(
                            "ALTER TABLE `{$table}` MODIFY `operating_system` VARCHAR(100) NOT NULL DEFAULT 'Unknown OS'",
                        );
                    }
                    if ($schema->hasColumn($table, 'browser')) {
                        $connection->statement(
                            "ALTER TABLE `{$table}` MODIFY `browser` VARCHAR(100) NOT NULL DEFAULT 'Unknown Browser'",
                        );
                    }

                    continue;
                }

                if ($driver === 'pgsql') {
                    if ($schema->hasColumn($table, 'operating_system')) {
                        $connection->statement(
                            "ALTER TABLE \"{$table}\" ALTER COLUMN \"operating_system\" TYPE VARCHAR(100)",
                        );
                    }
                    if ($schema->hasColumn($table, 'browser')) {
                        $connection->statement(
                            "ALTER TABLE \"{$table}\" ALTER COLUMN \"browser\" TYPE VARCHAR(100)",
                        );
                    }

                    continue;
                }

                try {
                    $schema->table($table, function (Blueprint $blueprint) use (
                        $schema,
                        $table,
                    ) {
                        if ($schema->hasColumn($table, 'operating_system')) {
                            $blueprint
                                ->string('operating_system', 100)
                                ->default('Unknown OS')
                                ->change();
                        }
                        if ($schema->hasColumn($table, 'browser')) {
                            $blueprint
                                ->string('browser', 100)
                                ->default('Unknown Browser')
                                ->change();
                        }
                    });
                } catch (Throwable) {
                    // Abaikan jika driver tidak mendukung
                }
            }
        }
    }
};
