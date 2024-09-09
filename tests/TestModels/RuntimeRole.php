<?php

namespace Elite\Permission\Tests\TestModels;

class RuntimeRole extends \Elite\Permission\Models\Role
{
    protected $visible = [
        'id',
        'name',
    ];
}
