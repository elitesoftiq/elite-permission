<?php

namespace Elite\Permission\Traits;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Elite\Permission\Contracts\AdminPermission as Permission;
use Elite\Permission\Contracts\AdminRole as Role;
use Elite\Permission\Contracts\Wildcard;
use Elite\Permission\Exceptions\GuardDoesNotMatch;
use Elite\Permission\Exceptions\PermissionDoesNotExist;
use Elite\Permission\Exceptions\WildcardPermissionInvalidArgument;
use Elite\Permission\Exceptions\WildcardPermissionNotImplementsContract;
use Elite\Permission\Guard;
use Elite\Permission\AdminPermissionRegistrar;
use Elite\Permission\WildcardPermission;

trait HasAdminPermissions
{
    private ?string $permissionClass = null;

    private ?string $wildcardClass = null;

    private array $wildcardPermissionsIndex;

    public static function bootHasAdminPermissions()
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            if (! is_a($model, Permission::class)) {
                $model->adminPermissions()->detach();
            }
            if (is_a($model, Role::class)) {
                $model->users()->detach();
            }
        });
    }

    public function getAdminPermissionClass(): string
    {
        if (! $this->permissionClass) {
            $this->permissionClass = app(AdminPermissionRegistrar::class)->getPermissionClass();
        }

        return $this->permissionClass;
    }

    public function getWildcardClass()
    {
        if (! is_null($this->wildcardClass)) {
            return $this->wildcardClass;
        }

        $this->wildcardClass = '';

        if (config('admin-permission.enable_wildcard_permission')) {
            $this->wildcardClass = config('admin-permission.wildcard_permission', WildcardPermission::class);

            if (! is_subclass_of($this->wildcardClass, Wildcard::class)) {
                throw WildcardPermissionNotImplementsContract::create();
            }
        }

        return $this->wildcardClass;
    }

    /**
     * A model may have multiple direct admin permissions.
     */
    public function adminPermissions(): BelongsToMany
    {
        $relation = $this->morphToMany(
            config('admin-permission.models.permission'),
            'model',
            config('admin-permission.table_names.model_has_permissions'),
            config('admin-permission.column_names.model_morph_key'),
            app(AdminPermissionRegistrar::class)->pivotPermission
        );

        return $relation;
    }

    /**
     * Scope the model query to certain admin permissions only.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     * @param  bool  $without
     */
    public function scopeAdminPermission(Builder $query, $permissions, $without = false): Builder
    {
        $permissions = $this->convertToAdminPermissionModels($permissions);

        $permissionKey = (new ($this->getAdminPermissionClass())())->getKeyName();
        $roleKey = (new (is_a($this, Role::class) ? static::class : $this->getAdminRoleClass())())->getKeyName();

        $rolesWithPermissions = is_a($this, Role::class) ? [] : array_unique(
            array_reduce($permissions, fn ($result, $permission) => array_merge($result, $permission->adminRoles->all()), [])
        );

        return $query->where(fn (Builder $query) => $query
            ->{! $without ? 'whereHas' : 'whereDoesntHave'}('adminPermissions', fn (Builder $subQuery) => $subQuery
            ->whereIn(config('admin-permission.table_names.permissions').".$permissionKey", \array_column($permissions, $permissionKey))
            )
            ->when(count($rolesWithPermissions), fn ($whenQuery) => $whenQuery
                ->{! $without ? 'orWhereHas' : 'whereDoesntHave'}('adminRoles', fn (Builder $subQuery) => $subQuery
                ->whereIn(config('admin-permission.table_names.roles').".$roleKey", \array_column($rolesWithPermissions, $roleKey))
                )
            )
        );
    }

    /**
     * Scope the model query to only those without certain admin permissions,
     * whether indirectly by admin role or by direct admin permission.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     */
    public function scopeWithoutAdminPermission(Builder $query, $permissions): Builder
    {
        return $this->scopeAdminPermission($query, $permissions, true);
    }

    /**
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     *
     * @throws PermissionDoesNotExist
     */
    protected function convertToAdminPermissionModels($permissions): array
    {
        if ($permissions instanceof Collection) {
            $permissions = $permissions->all();
        }

        return array_map(function ($permission) {
            if ($permission instanceof Permission) {
                return $permission;
            }

            if ($permission instanceof \BackedEnum) {
                $permission = $permission->value;
            }

            $method = is_int($permission) || AdminPermissionRegistrar::isUid($permission) ? 'findById' : 'findByName';

            return $this->getAdminPermissionClass()::{$method}($permission, $this->getDefaultGuardName());
        }, Arr::wrap($permissions));
    }

    /**
     * Find a admin permission.
     *
     * @param  string|int|Permission|\BackedEnum  $permission
     * @return Permission
     *
     * @throws PermissionDoesNotExist
     */
    public function filterAdminPermission($permission, $guardName = null)
    {
        if ($permission instanceof \BackedEnum) {
            $permission = $permission->value;
        }

        if (is_int($permission) || AdminPermissionRegistrar::isUid($permission)) {
            $permission = $this->getAdminPermissionClass()::findById(
                $permission,
                $guardName ?? $this->getDefaultGuardName()
            );
        }

        if (is_string($permission)) {
            $permission = $this->getAdminPermissionClass()::findByName(
                $permission,
                $guardName ?? $this->getDefaultGuardName()
            );
        }

        if (! $permission instanceof Permission) {
            throw new PermissionDoesNotExist();
        }

        return $permission;
    }

    /**
     * Determine if the model may perform the given admin permission.
     *
     * @param  string|int|Permission|\BackedEnum  $permission
     * @param  string|null  $guardName
     *
     * @throws PermissionDoesNotExist
     */
    public function hasAdminPermissionTo($permission, $guardName = null): bool
    {
        if ($this->getWildcardClass()) {
            return $this->hasWildcardAdminPermission($permission, $guardName);
        }

        $permission = $this->filterAdminPermission($permission, $guardName);

        return $this->hasDirectAdminPermission($permission) || $this->hasAdminPermissionViaRole($permission);
    }

    /**
     * Validates a wildcard admin permission against all admin permissions of a user.
     *
     * @param  string|int|Permission|\BackedEnum  $permission
     * @param  string|null  $guardName
     */
    protected function hasWildcardAdminPermission($permission, $guardName = null): bool
    {
        $guardName = $guardName ?? $this->getDefaultGuardName();

        if ($permission instanceof \BackedEnum) {
            $permission = $permission->value;
        }

        if (is_int($permission) || AdminPermissionRegistrar::isUid($permission)) {
            $permission = $this->getAdminPermissionClass()::findById($permission, $guardName);
        }

        if ($permission instanceof Permission) {
            $guardName = $permission->guard_name ?? $guardName;
            $permission = $permission->name;
        }

        if (! is_string($permission)) {
            throw WildcardPermissionInvalidArgument::create();
        }

        return app($this->getWildcardClass(), ['record' => $this])->implies(
            $permission,
            $guardName,
            app(AdminPermissionRegistrar::class)->getWildcardPermissionIndex($this),
        );
    }

    /**
     * An alias to hasAdminPermissionTo(), but avoids throwing an exception.
     *
     * @param  string|int|Permission|\BackedEnum  $permission
     * @param  string|null  $guardName
     */
    public function checkAdminPermissionTo($permission, $guardName = null): bool
    {
        try {
            return $this->hasAdminPermissionTo($permission, $guardName);
        } catch (PermissionDoesNotExist $e) {
            return false;
        }
    }

    /**
     * Determine if the model has any of the given admin permissions.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  ...$permissions
     */
    public function hasAnyAdminPermission(...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if ($this->checkAdminPermissionTo($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the model has all of the given admin permissions.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  ...$permissions
     */
    public function hasAllAdminPermissions(...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if (! $this->checkAdminPermissionTo($permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine if the model has, via admin roles, the given admin permission.
     */
    protected function hasAdminPermissionViaRole(Permission $permission): bool
    {
        if (is_a($this, Role::class)) {
            return false;
        }

        return $this->hasAdminRole($permission->roles);
    }

    /**
     * Determine if the model has the given admin permission.
     *
     * @param  string|int|Permission|\BackedEnum  $permission
     *
     * @throws PermissionDoesNotExist
     */
    public function hasDirectAdminPermission($permission): bool
    {
        $permission = $this->filterAdminPermission($permission);

        return $this->adminPermissions->contains($permission->getKeyName(), $permission->getKey());
    }

    /**
     * Return all the admin permissions the model has via admin roles.
     */
    public function getAdminPermissionsViaRoles(): Collection
    {
        if (is_a($this, Role::class) || is_a($this, Permission::class)) {
            return collect();
        }

        return $this->loadMissing('adminRoles', 'adminRoles.adminPermissions')
            ->roles->flatMap(fn ($role) => $role->permissions)
            ->sort()->values();
    }

    /**
     * Return all the admin permissions the model has, both directly and via admin roles.
     */
    public function getAllAdminPermissions(): Collection
    {
        /** @var Collection $permissions */
        $permissions = $this->adminPermissions;

        if (method_exists($this, 'adminRoles')) {
            $permissions = $permissions->merge($this->getAdminPermissionsViaRoles());
        }

        return $permissions->sort()->values();
    }

    /**
     * Returns array of admin permissions ids
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     */
    private function collectAdminPermissions(...$permissions): array
    {
        return collect($permissions)
            ->flatten()
            ->reduce(function ($array, $permission) {
                if (empty($permission)) {
                    return $array;
                }

                $permission = $this->getStoredAdminPermission($permission);
                if (! $permission instanceof Permission) {
                    return $array;
                }

                if (! in_array($permission->getKey(), $array)) {
                    $this->ensureModelSharesGuard($permission);
                    $array[] = $permission->getKey();
                }

                return $array;
            }, []);
    }

    /**
     * Grant the given admin permission(s) to a role.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     * @return $this
     */
    public function giveAdminPermissionTo(...$permissions)
    {
        $permissions = $this->collectAdminPermissions($permissions);

        $model = $this->getModel();

        if ($model->exists) {
            $currentPermissions = $this->adminPermissions->map(fn ($permission) => $permission->getKey())->toArray();

            $this->adminPermissions()->attach(array_diff($permissions, $currentPermissions), []);
            $model->unsetRelation('adminPermissions');
        } else {
            $class = \get_class($model);
            $saved = false;

            $class::saved(
                function ($object) use ($permissions, $model, &$saved) {
                    if ($saved || $model->getKey() != $object->getKey()) {
                        return;
                    }
                    $model->adminPermissions()->attach($permissions, []);
                    $model->unsetRelation('adminPermissions');
                    $saved = true;
                }
            );
        }

        if (is_a($this, Role::class)) {
            $this->forgetCachedAdminPermissions();
        }

        $this->forgetWildcardAdminPermissionIndex();

        return $this;
    }

    public function forgetWildcardAdminPermissionIndex(): void
    {
        app(AdminPermissionRegistrar::class)->forgetWildcardPermissionIndex(
            is_a($this, Role::class) ? null : $this,
        );
    }

    /**
     * Remove all current admin permissions and set the given ones.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     * @return $this
     */
    public function syncAdminPermissions(...$permissions)
    {
        if ($this->getModel()->exists) {
            $this->collectAdminPermissions($permissions);
            $this->adminPermissions()->detach();
            $this->setRelation('adminPermissions', collect());
        }

        return $this->givePermissionTo($permissions);
    }

    /**
     * Revoke the given admin permission(s).
     *
     * @param  Permission|Permission[]|string|string[]|\BackedEnum  $permission
     * @return $this
     */
    public function revokeAdminPermissionTo($permission)
    {
        $this->adminPermissions()->detach($this->getStoredAdminPermission($permission));

        if (is_a($this, Role::class)) {
            $this->forgetCachedAdminPermissions();
        }

        $this->forgetWildcardAdminPermissionIndex();

        $this->unsetRelation('adminPermissions');

        return $this;
    }

    public function getAdminPermissionNames(): Collection
    {
        return $this->adminPermissions->pluck('name');
    }

    /**
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     * @return Permission|Permission[]|Collection
     */
    protected function getStoredAdminPermission($permissions)
    {
        if ($permissions instanceof \BackedEnum) {
            $permissions = $permissions->value;
        }

        if (is_int($permissions) || AdminPermissionRegistrar::isUid($permissions)) {
            return $this->getAdminPermissionClass()::findById($permissions, $this->getDefaultGuardName());
        }

        if (is_string($permissions)) {
            return $this->getAdminPermissionClass()::findByName($permissions, $this->getDefaultGuardName());
        }

        if (is_array($permissions)) {
            $permissions = array_map(function ($permission) {
                if ($permission instanceof \BackedEnum) {
                    return $permission->value;
                }

                return is_a($permission, Permission::class) ? $permission->name : $permission;
            }, $permissions);

            return $this->getAdminPermissionClass()::whereIn('name', $permissions)
                ->whereIn('guard_name', $this->getGuardNames())
                ->get();
        }

        return $permissions;
    }

    /**
     * @param  Permission|Role  $roleOrPermission
     *
     * @throws GuardDoesNotMatch
     */
    protected function ensureModelSharesGuard($roleOrPermission)
    {
        if (! $this->getGuardNames()->contains($roleOrPermission->guard_name)) {
            throw GuardDoesNotMatch::create($roleOrPermission->guard_name, $this->getGuardNames());
        }
    }

    protected function getGuardNames(): Collection
    {
        return Guard::getNames($this);
    }

    protected function getDefaultGuardName(): string
    {
        return Guard::getDefaultName($this);
    }

    /**
     * Forget the cached admin permissions.
     */
    public function forgetCachedAdminPermissions()
    {
        app(AdminPermissionRegistrar::class)->forgetCachedPermissions();
    }

    /**
     * Check if the model has All of the requested Direct admin permissions.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  ...$permissions
     */
    public function hasAllDirectAdminPermissions(...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if (! $this->hasDirectAdminPermission($permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if the model has Any of the requested Direct admin permissions.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  ...$permissions
     */
    public function hasAnyDirectAdminPermission(...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if ($this->hasDirectAdminPermission($permission)) {
                return true;
            }
        }

        return false;
    }
}
