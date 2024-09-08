<?php

return [

    'models' => [

        /*
         * When using the "HasAdminPermissions" trait from this package, we need to know which
         * Eloquent model should be used to retrieve your admin permissions. Of course, it
         * is often just the "AdminPermission" model but you may use whatever you like.
         *
         * The model you want to use as a AdminPermission model needs to implement the
         * `Spatie\Permission\Contracts\AdminPermission` contract.
         */

        'permission' => Spatie\Permission\Models\AdminPermission::class,

        /*
         * When using the "HasAdminRoles" trait from this package, we need to know which
         * Eloquent model should be used to retrieve your admin roles. Of course, it
         * is often just the "AdminRole" model but you may use whatever you like.
         *
         * The model you want to use as a AdminRole model needs to implement the
         * `Spatie\Permission\Contracts\AdminRole` contract.
         */

        'role' => Spatie\Permission\Models\AdminRole::class,

    ],

    'table_names' => [

        /*
         * When using the "HasAdminRoles" trait from this package, we need to know which
         * table should be used to retrieve your admin roles. We have chosen a basic
         * default value but you may easily change it to any table you like.
         */

        'roles' => 'admin_roles',

        /*
         * When using the "HasAdminPermissions" trait from this package, we need to know which
         * table should be used to retrieve your admin permissions. We have chosen a basic
         * default value but you may easily change it to any table you like.
         */

        'permissions' => 'admin_permissions',

        /*
         * When using the "HasAdminPermissions" trait from this package, we need to know which
         * table should be used to retrieve your models admin permissions. We have chosen a
         * basic default value but you may easily change it to any table you like.
         */

        'model_has_permissions' => 'model_has_admin_permissions',

        /*
         * When using the "HasAdminRoles" trait from this package, we need to know which
         * table should be used to retrieve your models admin roles. We have chosen a
         * basic default value but you may easily change it to any table you like.
         */

        'model_has_roles' => 'model_has_admin_roles',

        /*
         * When using the "HasAdminRoles" trait from this package, we need to know which
         * table should be used to retrieve your admin roles permissions. We have chosen a
         * basic default value but you may easily change it to any table you like.
         */

        'role_has_permissions' => 'admin_role_has_admin_permissions',
    ],

    'column_names' => [
        /*
         * Change this if you want to name the related pivots other than defaults
         */
        'role_pivot_key' => null, //default 'admin_role_id',
        'permission_pivot_key' => null, //default 'admin_permission_id',

        /*
         * Change this if you want to name the related model primary key other than
         * `model_id`.
         *
         * For example, this would be nice if your primary keys are all UUIDs. In
         * that case, name this `model_uuid`.
         */

        'model_morph_key' => 'model_id',
    ],

    /*
     * When set to true, the method for checking admin permissions will be registered on the gate.
     * Set this to false if you want to implement custom logic for checking admin permissions.
     */

    'register_permission_check_method' => true,

    /*
     * When set to true, Laravel\Octane\Events\OperationTerminated event listener will be registered
     * this will refresh admin permissions on every TickTerminated, TaskTerminated and RequestTerminated
     * NOTE: This should not be needed in most cases, but an Octane/Vapor combination benefited from it.
     */
    'register_octane_reset_listener' => false,

    /*
     * By default wildcard admin permission lookups are disabled.
     * See documentation to understand supported syntax.
     */

    'enable_wildcard_permission' => false,

    /*
     * The class to use for interpreting wildcard admin permissions.
     * If you need to modify delimiters, override the class and specify its name here.
     */
    // 'permission.wildcard_permission' => Spatie\Permission\WildcardPermission::class,

    /* Cache-specific settings */

    'cache' => [

        /*
         * By default all admin permissions are cached for 24 hours to speed up performance.
         * When admin permissions or roles are updated the cache is flushed automatically.
         */

        'expiration_time' => \DateInterval::createFromDateString('24 hours'),

        /*
         * The cache key used to store all admin permissions.
         */

        'key' => 'elite.admin-permission.cache',

        /*
         * You may optionally indicate a specific cache driver to use for admin permission and
         * role caching using any of the `store` drivers listed in the cache.php config
         * file. Using 'default' here means to use the `default` set in cache.php.
         */

        'store' => 'default',
    ],
];
