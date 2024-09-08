<?php

namespace Elite\Permission\Contracts;

use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * @property int|string $id
 * @property string $name
 * @property string|null $guard_name
 *
 * @mixin \Elite\Permission\Models\AdminPermission
 *
 * @phpstan-require-extends \Elite\Permission\Models\AdminPermission
 */
interface AdminPermission
{
    /**
     * An admin permission can be applied to admin roles.
     */
    public function adminRoles(): BelongsToMany;

    /**
     * Find a admin permission by its name.
     *
     *
     * @throws \Elite\Permission\Exceptions\PermissionDoesNotExist
     */
    public static function findByName(string $name, ?string $guardName): self;

    /**
     * Find a admin permission by its id.
     *
     *
     * @throws \Elite\Permission\Exceptions\PermissionDoesNotExist
     */
    public static function findById(int|string $id, ?string $guardName): self;

    /**
     * Find or Create an admin permission by its name and guard name.
     */
    public static function findOrCreate(string $name, ?string $guardName): self;
}
