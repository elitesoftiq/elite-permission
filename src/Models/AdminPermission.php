<?php

namespace Elite\Permission\Models;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Elite\Permission\Contracts\AdminPermission as PermissionContract;
use Elite\Permission\Exceptions\PermissionAlreadyExists;
use Elite\Permission\Exceptions\PermissionDoesNotExist;
use Elite\Permission\Guard;
use Elite\Permission\AdminPermissionRegistrar;
use Elite\Permission\Traits\HasAdminRoles;
use Elite\Permission\Traits\RefreshesAdminPermissionCache;

/**
 * @property ?\Illuminate\Support\Carbon $created_at
 * @property ?\Illuminate\Support\Carbon $updated_at
 */
class AdminPermission extends Model implements PermissionContract
{
    use HasAdminRoles;
    use RefreshesAdminPermissionCache;

    protected $guarded = [];

    public function __construct(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? config('auth.defaults.guard');

        parent::__construct($attributes);

        $this->guarded[] = $this->primaryKey;
        $this->table = config('admin-permission.table_names.permissions') ?: parent::getTable();
    }

    /**
     * @return PermissionContract|AdminPermission
     *
     * @throws PermissionAlreadyExists
     */
    public static function create(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? Guard::getDefaultName(static::class);

        $permission = static::getPermission(['name' => $attributes['name'], 'guard_name' => $attributes['guard_name']]);

        if ($permission) {
            throw PermissionAlreadyExists::create($attributes['name'], $attributes['guard_name']);
        }

        return static::query()->create($attributes);
    }

    /**
     * An admin permission can be applied to admin roles.
     */
    public function adminRoles(): BelongsToMany
    {
        return $this->belongsToMany(
            config('admin-permission.models.role'),
            config('admin-permission.table_names.role_has_permissions'),
            app(AdminPermissionRegistrar::class)->pivotPermission,
            app(AdminPermissionRegistrar::class)->pivotRole
        );
    }

    /**
     * An admin permission belongs to some users of the model associated with its guard.
     */
    public function users(): BelongsToMany
    {
        return $this->morphedByMany(
            getModelForGuard($this->attributes['guard_name'] ?? config('auth.defaults.guard')),
            'model',
            config('admin-permission.table_names.model_has_permissions'),
            app(AdminPermissionRegistrar::class)->pivotPermission,
            config('admin-permission.column_names.model_morph_key')
        );
    }

    /**
     * Find an admin permission by its name (and optionally guardName).
     *
     * @return PermissionContract|AdminPermission
     *
     * @throws PermissionDoesNotExist
     */
    public static function findByName(string $name, ?string $guardName = null): PermissionContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);
        $permission = static::getPermission(['name' => $name, 'guard_name' => $guardName]);
        if (! $permission) {
            throw PermissionDoesNotExist::create($name, $guardName);
        }

        return $permission;
    }

    /**
     * Find a admin permission by its id (and optionally guardName).
     *
     * @return PermissionContract|AdminPermission
     *
     * @throws PermissionDoesNotExist
     */
    public static function findById(int|string $id, ?string $guardName = null): PermissionContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);
        $permission = static::getPermission([(new static())->getKeyName() => $id, 'guard_name' => $guardName]);

        if (! $permission) {
            throw PermissionDoesNotExist::withId($id, $guardName);
        }

        return $permission;
    }

    /**
     * Find or create admin permission by its name (and optionally guardName).
     *
     * @return PermissionContract|AdminPermission
     */
    public static function findOrCreate(string $name, ?string $guardName = null): PermissionContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);
        $permission = static::getPermission(['name' => $name, 'guard_name' => $guardName]);

        if (! $permission) {
            return static::query()->create(['name' => $name, 'guard_name' => $guardName]);
        }

        return $permission;
    }

    /**
     * Get the current cached admin permissions.
     */
    protected static function getPermissions(array $params = [], bool $onlyOne = false): Collection
    {
        return app(AdminPermissionRegistrar::class)
            ->setPermissionClass(static::class)
            ->getPermissions($params, $onlyOne);
    }

    /**
     * Get the current cached first admin permission.
     *
     * @return PermissionContract|AdminPermission|null
     */
    protected static function getPermission(array $params = []): ?PermissionContract
    {
        /** @var PermissionContract|null */
        return static::getPermissions($params, true)->first();
    }
}
