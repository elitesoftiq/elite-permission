<?php

namespace Elite\Permission\Traits;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Elite\Permission\Contracts\AdminPermission as Permission;
use Elite\Permission\Contracts\AdminRole as Role;
use Elite\Permission\AdminPermissionRegistrar;

trait HasAdminRoles
{
    use HasAdminPermissions;

    private ?string $roleClass = null;

    public static function bootHasAdminRoles()
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            $model->adminRoles()->detach();
            if (is_a($model, Permission::class)) {
                $model->users()->detach();
            }
        });
    }

    public function getAdminRoleClass(): string
    {
        if (! $this->roleClass) {
            $this->roleClass = app(AdminPermissionRegistrar::class)->getRoleClass();
        }

        return $this->roleClass;
    }

    /**
     * A model may have multiple admin roles.
     */
    public function adminRoles(): BelongsToMany
    {
        $relation = $this->morphToMany(
            config('admin-permission.models.role'),
            'model',
            config('admin-permission.table_names.model_has_roles'),
            config('admin-permission.column_names.model_morph_key'),
            app(AdminPermissionRegistrar::class)->pivotRole
        );

        return $relation;
    }

    /**
     * Scope the model query to certain roles only.
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  $roles
     * @param  string  $guard
     * @param  bool  $without
     */
    public function scopeAdminRole(Builder $query, $roles, $guard = null, $without = false): Builder
    {
        if ($roles instanceof Collection) {
            $roles = $roles->all();
        }

        $roles = array_map(function ($role) use ($guard) {
            if ($role instanceof Role) {
                return $role;
            }

            if ($role instanceof \BackedEnum) {
                $role = $role->value;
            }

            $method = is_int($role) || AdminPermissionRegistrar::isUid($role) ? 'findById' : 'findByName';

            return $this->getAdminRoleClass()::{$method}($role, $guard ?: $this->getDefaultGuardName());
        }, Arr::wrap($roles));

        $key = (new ($this->getAdminRoleClass())())->getKeyName();

        return $query->{! $without ? 'whereHas' : 'whereDoesntHave'}('adminRoles', fn (Builder $subQuery) => $subQuery
            ->whereIn(config('admin-permission.table_names.roles').".$key", \array_column($roles, $key))
        );
    }

    /**
     * Scope the model query to only those without certain admin roles.
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  $roles
     * @param  string  $guard
     */
    public function scopeWithoutAdminRole(Builder $query, $roles, $guard = null): Builder
    {
        return $this->scopeAdminRole($query, $roles, $guard, true);
    }

    /**
     * Returns array of admin role ids
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  $roles
     */
    private function collectAdminRoles(...$roles): array
    {
        return collect($roles)
            ->flatten()
            ->reduce(function ($array, $role) {
                if (empty($role)) {
                    return $array;
                }

                $role = $this->getStoredAdminRole($role);
                if (! $role instanceof Role) {
                    return $array;
                }

                if (! in_array($role->getKey(), $array)) {
                    $this->ensureModelSharesGuard($role);
                    $array[] = $role->getKey();
                }

                return $array;
            }, []);
    }

    /**
     * Assign the given admin role to the model.
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  ...$roles
     * @return $this
     */
    public function assignAdminRole(...$roles)
    {
        $roles = $this->collectAdminRoles($roles);

        $model = $this->getModel();

        if ($model->exists) {
            $currentRoles = $this->adminRoles->map(fn ($role) => $role->getKey())->toArray();

            $this->adminRoles()->attach(array_diff($roles, $currentRoles), []);
            $model->unsetRelation('adminRoles');
        } else {
            $class = \get_class($model);
            $saved = false;

            $class::saved(
                function ($object) use ($roles, $model, &$saved) {
                    if ($saved || $model->getKey() != $object->getKey()) {
                        return;
                    }
                    $model->adminRoles()->attach($roles, []);
                    $model->unsetRelation('adminRoles');
                    $saved = true;
                }
            );
        }

        if (is_a($this, Permission::class)) {
            $this->forgetCachedAdminPermissions();
        }

        return $this;
    }

    /**
     * Revoke the given admin role from the model.
     *
     * @param  string|int|Role|\BackedEnum  $role
     */
    public function removeAdminRole($role)
    {
        $this->adminRoles()->detach($this->getStoredAdminRole($role));

        $this->unsetRelation('adminRoles');

        if (is_a($this, Permission::class)) {
            $this->forgetCachedAdminPermissions();
        }

        return $this;
    }

    /**
     * Remove all current admin roles and set the given ones.
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  ...$roles
     * @return $this
     */
    public function syncAdminRoles(...$roles)
    {
        if ($this->getModel()->exists) {
            $this->collectAdminRoles($roles);
            $this->adminRoles()->detach();
            $this->setRelation('adminRoles', collect());
        }

        return $this->assignAdminRole($roles);
    }

    /**
     * Determine if the model has (one of) the given role(s).
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  $roles
     */
    public function hasAdminRole($roles, ?string $guard = null): bool
    {
        $this->loadMissing('adminRoles');

        if (is_string($roles) && strpos($roles, '|') !== false) {
            $roles = $this->convertPipeToArray($roles);
        }

        if ($roles instanceof \BackedEnum) {
            $roles = $roles->value;

            return $this->adminRoles
                ->when($guard, fn ($q) => $q->where('guard_name', $guard))
                ->pluck('name')
                ->contains(function ($name) use ($roles) {
                    /** @var string|\BackedEnum $name */
                    if ($name instanceof \BackedEnum) {
                        return $name->value == $roles;
                    }

                    return $name == $roles;
                });
        }

        if (is_int($roles) || AdminPermissionRegistrar::isUid($roles)) {
            $key = (new ($this->getAdminRoleClass())())->getKeyName();

            return $guard
                ? $this->adminRoles->where('guard_name', $guard)->contains($key, $roles)
                : $this->adminRoles->contains($key, $roles);
        }

        if (is_string($roles)) {
            return $guard
                ? $this->adminRoles->where('guard_name', $guard)->contains('name', $roles)
                : $this->adminRoles->contains('name', $roles);
        }

        if ($roles instanceof Role) {
            return $this->adminRoles->contains($roles->getKeyName(), $roles->getKey());
        }

        if (is_array($roles)) {
            foreach ($roles as $role) {
                if ($this->hasAdminRole($role, $guard)) {
                    return true;
                }
            }

            return false;
        }

        if ($roles instanceof Collection) {
            return $roles->intersect($guard ? $this->adminRoles->where('guard_name', $guard) : $this->adminRoles)->isNotEmpty();
        }

        throw new \TypeError('Unsupported type for $roles parameter to hasAdminRole().');
    }

    /**
     * Determine if the model has any of the given admin role(s).
     *
     * Alias to hasAdminRole() but without Guard controls
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  $roles
     */
    public function hasAnyAdminRole(...$roles): bool
    {
        return $this->hasAdminRole($roles);
    }

    /**
     * Determine if the model has all of the given admin role(s).
     *
     * @param  string|array|Role|Collection|\BackedEnum  $roles
     */
    public function hasAllAdminRoles($roles, ?string $guard = null): bool
    {
        $this->loadMissing('adminRoles');

        if ($roles instanceof \BackedEnum) {
            $roles = $roles->value;
        }

        if (is_string($roles) && strpos($roles, '|') !== false) {
            $roles = $this->convertPipeToArray($roles);
        }

        if (is_string($roles)) {
            return $this->hasAdminRole($roles, $guard);
        }

        if ($roles instanceof Role) {
            return $this->adminRoles->contains($roles->getKeyName(), $roles->getKey());
        }

        $roles = collect()->make($roles)->map(function ($role) {
            if ($role instanceof \BackedEnum) {
                return $role->value;
            }

            return $role instanceof Role ? $role->name : $role;
        });

        $roleNames = $guard
            ? $this->adminRoles->where('guard_name', $guard)->pluck('name')
            : $this->getAdminRoleNames();

        $roleNames = $roleNames->transform(function ($roleName) {
            if ($roleName instanceof \BackedEnum) {
                return $roleName->value;
            }

            return $roleName;
        });

        return $roles->intersect($roleNames) == $roles;
    }

    /**
     * Determine if the model has exactly all of the given admin role(s).
     *
     * @param  string|array|Role|Collection|\BackedEnum  $roles
     */
    public function hasExactAdminRoles($roles, ?string $guard = null): bool
    {
        $this->loadMissing('adminRoles');

        if (is_string($roles) && strpos($roles, '|') !== false) {
            $roles = $this->convertPipeToArray($roles);
        }

        if (is_string($roles)) {
            $roles = [$roles];
        }

        if ($roles instanceof Role) {
            $roles = [$roles->name];
        }

        $roles = collect()->make($roles)->map(fn ($role) => $role instanceof Role ? $role->name : $role
        );

        return $this->adminRoles->count() == $roles->count() && $this->hasAllAdminRoles($roles, $guard);
    }

    /**
     * Return all admin permissions directly coupled to the model.
     */
    public function getDirectAdminPermissions(): Collection
    {
        return $this->adminPermissions;
    }

    public function getAdminRoleNames(): Collection
    {
        $this->loadMissing('adminRoles');

        return $this->adminRoles->pluck('name');
    }

    protected function getStoredAdminRole($role): Role
    {
        if ($role instanceof \BackedEnum) {
            $role = $role->value;
        }

        if (is_int($role) || AdminPermissionRegistrar::isUid($role)) {
            return $this->getAdminRoleClass()::findById($role, $this->getDefaultGuardName());
        }

        if (is_string($role)) {
            return $this->getAdminRoleClass()::findByName($role, $this->getDefaultGuardName());
        }

        return $role;
    }

    protected function convertPipeToArray(string $pipeString)
    {
        $pipeString = trim($pipeString);

        if (strlen($pipeString) <= 2) {
            return [str_replace('|', '', $pipeString)];
        }

        $quoteCharacter = substr($pipeString, 0, 1);
        $endCharacter = substr($quoteCharacter, -1, 1);

        if ($quoteCharacter !== $endCharacter) {
            return explode('|', $pipeString);
        }

        if (! in_array($quoteCharacter, ["'", '"'])) {
            return explode('|', $pipeString);
        }

        return explode('|', trim($pipeString, $quoteCharacter));
    }
}
