<?php

namespace Spatie\Permission\Commands;

use Illuminate\Console\Command;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\AdminPermissionRegistrar;

class CacheReset extends Command
{
    protected $signature = 'permission:cache-reset';

    protected $description = 'Reset the permission cache';

    public function handle()
    {
        if (app(PermissionRegistrar::class)->forgetCachedPermissions() && app(AdminPermissionRegistrar::class)->forgetCachedPermissions()) {
            $this->info('Permission cache flushed.');
        } else {
            $this->error('Unable to flush cache.');
        }
    }
}
