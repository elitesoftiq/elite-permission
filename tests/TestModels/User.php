<?php

namespace Elite\Permission\Tests\TestModels;

use Elite\Permission\Traits\HasRoles;

class User extends UserWithoutHasRoles
{
    use HasRoles;
}
