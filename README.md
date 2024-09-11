# ElitePermission
In most SaaS applications, you have two main sides: one for companies or organizations, and another for administrators who manage the SaaS product itself. Both sides need to handle their own roles and permissions is separate way. That's why we developed this package (ElitePermission) to manage permissions for both teams (organizations) and administrators in our projects.

ElitePermission is a Laravel package, built on top of the popular [spatie/permission](https://github.com/spatie/laravel-permission) package, with added custom features designed to support SaaS applications. It helps manage roles and permissions in multi-tenant environments, making it easier to handle user access across different tenants. 

## The Problem
The main limitation of the original spatie/permission package is that it doesn't support both teams and global permissions at the same time. Once you enable team-based permissions, you're forced to assign roles and permissions within teams only. There's no flexibility to change this behavior because the team ID is stored globally using a middleware, preventing you from passing it dynamically through function parameters.

We also needed to completely separate admin permissions from teams permissions using different tables.

## The Solution
We chose a simple solution by introducing two types of roles and permissions: 
- The original ones for teams (or tenants in our case) 
- The new ones specifically for administrators, which don't rely on the teams feature. This allows our team to handle both team-based and global permissions without a lot of customization on the logic.

## Documentation
You can still use [Spatie's official documentation](https://spatie.be/docs/laravel-permission/v6/installation-laravel), since we haven't removed any core functionality. The key difference is that we've added new versions of most permission-checking functions. The original versions still handle team-based permissions, while the newly added ones allow for checking permissions and roles specifically for administrators, without the teams feature.

For example, if you're used to checking if a user has a specific permission using the `hasPermissionTo` function, you can still use this function, but keep in mind that it will apply only to the current team. For administrators, we've introduced a new version of this function called `hasAdminPermissionTo`, which checks permissions without the team context. 

 On the user model you only need to add one additional trait to support administrators permissions and roles
 ```
 class User extends Model
 {
	 use HasRoles;                // For checking teams permissions
+   use HasAdminRoles;           // For checking admin permissions

		...
}
```

Finally you need to know that now you have an admin version of each table, Eloquent model and configuration.
