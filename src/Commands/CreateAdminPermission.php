<?php

namespace Elite\Permission\Commands;

use Illuminate\Console\Command;
use Elite\Permission\Contracts\AdminPermission as PermissionContract;

class CreateAdminPermission extends Command
{
    protected $signature = 'permission:create-admin-permission
                {name : The name of the permission}
                {guard? : The name of the guard}';

    protected $description = 'Create a admin permission';

    public function handle()
    {
        $permissionClass = app(PermissionContract::class);

        $permission = $permissionClass::findOrCreate($this->argument('name'), $this->argument('guard'));

        $this->info("Admin permission `{$permission->name}` ".($permission->wasRecentlyCreated ? 'created' : 'already exists'));
    }
}
