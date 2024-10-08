<?php

namespace Elite\Permission\Contracts;

use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * @property int|string $id
 * @property string $name
 * @property string|null $guard_name
 *
 * @mixin \Elite\Permission\Models\AdminRole
 *
 * @phpstan-require-extends \Elite\Permission\Models\AdminRole
 */
interface AdminRole
{
    /**
     * An admin role may be given various admin permissions.
     */
    public function adminPermissions(): BelongsToMany;

    /**
     * Find an admin role by its name and guard name.
     *
     *
     * @throws \Elite\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findByName(string $name, ?string $guardName): self;

    /**
     * Find an admin role by its id and guard name.
     *
     *
     * @throws \Elite\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findById(int|string $id, ?string $guardName): self;

    /**
     * Find or create an admin role by its name and guard name.
     */
    public static function findOrCreate(string $name, ?string $guardName): self;

    /**
     * Determine if the user may perform the given admin permission.
     *
     * @param  string|int|\Elite\Permission\Contracts\AdminPermission|\BackedEnum  $permission
     */
    public function hasAdminPermissionTo($permission, ?string $guardName): bool;
}
