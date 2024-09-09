<?php

namespace Elite\Permission\Tests\TestModels;

class Admin extends User
{
    protected $table = 'admins';

    protected $touches = ['roles', 'permissions'];
}
