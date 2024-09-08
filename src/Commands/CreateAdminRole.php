<?php

namespace Spatie\Permission\Commands;

use Illuminate\Console\Command;
use Spatie\Permission\Contracts\AdminPermission as PermissionContract;
use Spatie\Permission\Contracts\AdminRole as RoleContract;
use Spatie\Permission\AdminPermissionRegistrar;

class CreateAdminRole extends Command
{
    protected $signature = 'permission:create-admin-role
        {name : The name of the role}
        {guard? : The name of the guard}
        {permissions? : A list of admin permissions to assign to the admin role, separated by | }';

    protected $description = 'Create a admin role';

    public function handle()
    {
        $roleClass = app(RoleContract::class);

        $role = $roleClass::findOrCreate($this->argument('name'), $this->argument('guard'));

        $role->givePermissionTo($this->makePermissions($this->argument('permissions')));

        $this->info("Admin role `{$role->name}` ".($role->wasRecentlyCreated ? 'created' : 'updated'));
    }

    /**
     * @param  array|null|string  $string
     */
    protected function makePermissions($string = null)
    {
        if (empty($string)) {
            return;
        }

        $permissionClass = app(PermissionContract::class);

        $permissions = explode('|', $string);

        $models = [];

        foreach ($permissions as $permission) {
            $models[] = $permissionClass::findOrCreate(trim($permission), $this->argument('guard'));
        }

        return collect($models);
    }
}
