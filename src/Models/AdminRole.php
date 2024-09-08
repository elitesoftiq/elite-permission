<?php

namespace Elite\Permission\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Elite\Permission\Contracts\AdminRole as RoleContract;
use Elite\Permission\Exceptions\GuardDoesNotMatch;
use Elite\Permission\Exceptions\PermissionDoesNotExist;
use Elite\Permission\Exceptions\RoleAlreadyExists;
use Elite\Permission\Exceptions\RoleDoesNotExist;
use Elite\Permission\Guard;
use Elite\Permission\AdminPermissionRegistrar;
use Elite\Permission\Traits\HasAdminPermissions;
use Elite\Permission\Traits\RefreshesAdminPermissionCache;

/**
 * @property ?\Illuminate\Support\Carbon $created_at
 * @property ?\Illuminate\Support\Carbon $updated_at
 */
class AdminRole extends Model implements RoleContract
{
    use HasAdminPermissions;
    use RefreshesAdminPermissionCache;

    protected $guarded = [];

    public function __construct(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? config('auth.defaults.guard');

        parent::__construct($attributes);

        $this->guarded[] = $this->primaryKey;
        $this->table = config('admin-permission.table_names.roles') ?: parent::getTable();
    }

    /**
     * @return RoleContract|AdminRole
     *
     * @throws RoleAlreadyExists
     */
    public static function create(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? Guard::getDefaultName(static::class);

        $params = ['name' => $attributes['name'], 'guard_name' => $attributes['guard_name']];
        if (static::findByParam($params)) {
            throw RoleAlreadyExists::create($attributes['name'], $attributes['guard_name']);
        }

        return static::query()->create($attributes);
    }

    /**
     * An admin role may be given various admin permissions.
     */
    public function adminPermissions(): BelongsToMany
    {
        return $this->belongsToMany(
            config('admin-permission.models.permission'),
            config('admin-permission.table_names.role_has_permissions'),
            app(AdminPermissionRegistrar::class)->pivotRole,
            app(AdminPermissionRegistrar::class)->pivotPermission
        );
    }

    /**
     * An admin role belongs to some users of the model associated with its guard.
     */
    public function users(): BelongsToMany
    {
        return $this->morphedByMany(
            getModelForGuard($this->attributes['guard_name'] ?? config('auth.defaults.guard')),
            'model',
            config('admin-permission.table_names.model_has_roles'),
            app(AdminPermissionRegistrar::class)->pivotRole,
            config('admin-permission.column_names.model_morph_key')
        );
    }

    /**
     * Find an admin role by its name and guard name.
     *
     * @return RoleContract|AdminRole
     *
     * @throws RoleDoesNotExist
     */
    public static function findByName(string $name, ?string $guardName = null): RoleContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $role = static::findByParam(['name' => $name, 'guard_name' => $guardName]);

        if (! $role) {
            throw RoleDoesNotExist::named($name, $guardName);
        }

        return $role;
    }

    /**
     * Find an admin role by its id (and optionally guardName).
     *
     * @return RoleContract|AdminRole
     */
    public static function findById(int|string $id, ?string $guardName = null): RoleContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $role = static::findByParam([(new static())->getKeyName() => $id, 'guard_name' => $guardName]);

        if (! $role) {
            throw RoleDoesNotExist::withId($id, $guardName);
        }

        return $role;
    }

    /**
     * Find or create admin role by its name (and optionally guardName).
     *
     * @return RoleContract|AdminRole
     */
    public static function findOrCreate(string $name, ?string $guardName = null): RoleContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $role = static::findByParam(['name' => $name, 'guard_name' => $guardName]);

        if (! $role) {
            return static::query()->create(['name' => $name, 'guard_name' => $guardName]);
        }

        return $role;
    }

    /**
     * Finds a admin role based on an array of parameters.
     *
     * @return RoleContract|AdminRole|null
     */
    protected static function findByParam(array $params = []): ?RoleContract
    {
        $query = static::query();

        foreach ($params as $key => $value) {
            $query->where($key, $value);
        }

        return $query->first();
    }

    /**
     * Determine if the admin role may perform the given admin permission.
     *
     * @param  string|int|\Elite\Permission\Contracts\Permission|\BackedEnum  $permission
     *
     * @throws PermissionDoesNotExist|GuardDoesNotMatch
     */
    public function hasAdminPermissionTo($permission, ?string $guardName = null): bool
    {
        if ($this->getWildcardClass()) {
            return $this->hasWildcardAdminPermission($permission, $guardName);
        }

        $permission = $this->filterAdminPermission($permission, $guardName);

        if (! $this->getGuardNames()->contains($permission->guard_name)) {
            throw GuardDoesNotMatch::create($permission->guard_name, $guardName ?? $this->getGuardNames());
        }

        return $this->adminPermissions->contains($permission->getKeyName(), $permission->getKey());
    }
}
