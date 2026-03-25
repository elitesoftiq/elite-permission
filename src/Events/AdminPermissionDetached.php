<?php

declare(strict_types=1);

namespace Elite\Permission\Events;

use Illuminate\Database\Eloquent\Model;

class AdminPermissionDetached
{
    /**
     * Internally the trait passes the detached admin permission model instance.
     * A listener should inspect the received value type before using it.
     *
     * @param  \Elite\Permission\Contracts\AdminPermission|\Elite\Permission\Contracts\AdminPermission[]|array|int[]|string[]|\Illuminate\Support\Collection  $permissionsOrIds
     */
    public function __construct(
        public Model $model,
        public mixed $permissionsOrIds,
    ) {
    }
}

