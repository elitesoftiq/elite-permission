<?php

namespace Elite\Permission\Exceptions;

use InvalidArgumentException;

class WildcardPermissionNotImplementsContract extends InvalidArgumentException
{
    public static function create()
    {
        return new static('Wildcard permission class must implements Elite\Permission\Contracts\Wildcard contract');
    }
}
