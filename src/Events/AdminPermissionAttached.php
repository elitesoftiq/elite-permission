<?php

declare(strict_types=1);

namespace Elite\Permission\Events;

use Illuminate\Database\Eloquent\Model;

class AdminPermissionAttached
{
    /**
     * Internally the trait passes an array of admin permission ids (e.g. int's or uuid's).
     * A listener should inspect the received value type before using it.
     *
     * @param  array|int[]|string[]|\Elite\Permission\Contracts\AdminPermission|\Elite\Permission\Contracts\AdminPermission[]|\Illuminate\Support\Collection  $permissionsOrIds
     */
    public function __construct(
        public Model $model,
        public mixed $permissionsOrIds,
    ) {
    }
}

