<?php

namespace Pasax\SecureMonitor\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;
use Pasax\SecureMonitor\Support\PasaxDatabase;
use Pasax\SecureMonitor\Support\PasaxTableResolver;

trait ResolvesPasaxTable
{
    /**
     * Route all Pasax models to the dedicated isolated database connection (`pasax_sqlite` by default).
     */
    public function getConnectionName(): ?string
    {
        return PasaxDatabase::connectionName();
    }

    /**
     * Resolve the actual database table name with seamless backward compatibility.
     */
    public static function resolvePasaxTable(
        string $key,
        string $configured,
        string $legacy,
        string $prefixed,
    ): string {
        return PasaxTableResolver::resolve(
            $key,
            $configured,
            $legacy,
            $prefixed,
        );
    }

    /**
     * Reset the cached resolved table names (useful for tests and migrations).
     */
    public static function clearResolvedTableCache(): void
    {
        PasaxTableResolver::clearCache();
    }

    /**
     * Route belongsTo relationships targeting host models (e.g. App\Models\User)
     * to the host default database connection when Pasax uses an isolated connection.
     *
     * @template TRelatedModel of Model
     *
     * @param  class-string<TRelatedModel>  $related
     * @return BelongsTo<TRelatedModel, $this>
     */
    protected function belongsToHostModel(
        string $related,
        ?string $foreignKey = null,
        ?string $ownerKey = null,
        ?string $relation = null,
    ): BelongsTo {
        if ($relation === null) {
            $relation = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)[1]['function'] ?? 'user';
        }

        $instance = $this->newRelatedInstance($related);

        if (PasaxDatabase::isSeparateConnection() && $instance->getConnectionName() === $this->getConnectionName()) {
            $defaultConn = (string) config('database.default', '');
            if ($defaultConn !== '') {
                $instance->setConnection($defaultConn);
            }
        }

        if ($foreignKey === null) {
            $foreignKey = Str::snake($relation).'_'.$instance->getKeyName();
        }

        $ownerKey = $ownerKey ?: $instance->getKeyName();

        return $this->newBelongsTo(
            $instance->newQuery(),
            $this,
            $foreignKey,
            $ownerKey,
            $relation,
        );
    }
}
