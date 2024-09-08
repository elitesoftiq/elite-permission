<?php

namespace Spatie\Permission\Traits;

use Spatie\Permission\AdminPermissionRegistrar;

trait RefreshesAdminPermissionCache
{
    public static function bootRefreshesAdminPermissionCache()
    {
        static::saved(function () {
            app(AdminPermissionRegistrar::class)->forgetCachedPermissions();
        });

        static::deleted(function () {
            app(AdminPermissionRegistrar::class)->forgetCachedPermissions();
        });
    }
}
