## Documentation, Installation, and Usage Instructions

See the [documentation](https://spatie.be/docs/laravel-permission/) for detailed installation and usage instructions.

## What It Does

This package allows you to manage user permissions and roles in a database.

Once installed you can do stuff like this:

```php
// Adding permissions to a user
$user->givePermissionTo('edit articles');

// Adding permissions via a role
$user->assignRole('writer');

$role->givePermissionTo('edit articles');
```

Because all permissions will be registered on [Laravel's gate](https://laravel.com/docs/authorization), you can check if a user has a permission with Laravel's default `can` function:

```php
$user->can('edit articles');
```

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
