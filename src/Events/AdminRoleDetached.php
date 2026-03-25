<?php

declare(strict_types=1);

namespace Elite\Permission\Events;

use Illuminate\Database\Eloquent\Model;

class AdminRoleDetached
{
    /**
     * Internally the trait passes the detached admin role ids (e.g. int's or uuid's).
     * A listener should inspect the received value type before using it.
     *
     * @param  array|int[]|string[]|\Elite\Permission\Contracts\AdminRole|\Elite\Permission\Contracts\AdminRole[]|\Illuminate\Support\Collection  $rolesOrIds
     */
    public function __construct(
        public Model $model,
        public mixed $rolesOrIds,
    ) {
    }
}

