<?php

namespace Spatie\Permission\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Spatie\Permission\Contracts\AdminPermission as PermissionContract;
use Spatie\Permission\Contracts\AdminRole as RoleContract;
use Symfony\Component\Console\Helper\TableCell;

class ShowAdmin extends Command
{
    protected $signature = 'permission:show-admin
            {guard? : The name of the guard}
            {style? : The display style (default|borderless|compact|box)}';

    protected $description = 'Show a table of admin roles and permissions per guard';

    public function handle()
    {
        $permissionClass = app(PermissionContract::class);
        $roleClass = app(RoleContract::class);

        $style = $this->argument('style') ?? 'default';
        $guard = $this->argument('guard');

        if ($guard) {
            $guards = Collection::make([$guard]);
        } else {
            $guards = $permissionClass::pluck('guard_name')->merge($roleClass::pluck('guard_name'))->unique();
        }

        foreach ($guards as $guard) {
            $this->info("Guard: $guard");

            $roles = $roleClass::whereGuardName($guard)
                ->with('adminPermissions')
                ->orderBy('name')->get()->mapWithKeys(fn ($role) => [
                    $role->name => [
                        'permissions' => $role->adminPermissions->pluck($permissionClass->getKeyName())
                    ],
                ]);

            $permissions = $permissionClass::whereGuardName($guard)->orderBy('name')->pluck('name', $permissionClass->getKeyName());

            $body = $permissions->map(fn ($permission, $id) => $roles->map(
                fn (array $role_data) => $role_data['permissions']->contains($id) ? ' ✔' : ' ·'
            )->prepend($permission)
            );

            $this->table(
                array_merge(
                    isset($teams) ? $teams->prepend(new TableCell(''))->toArray() : [],
                    $roles->keys()->map(function ($val) {
                        $name = explode('_', $val);
                        array_pop($name);

                        return implode('_', $name);
                    })
                        ->prepend(new TableCell(''))->toArray(),
                ),
                $body->toArray(),
                $style
            );
        }
    }
}
