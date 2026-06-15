# Internal Server Error Analysis

## Problem
The error `ErrorException: Attempt to read property "id" on null` indicates that the application is trying to access an `id` property on an object that evaluates to `null`. This specific crash originates from `App\Http\Resources\CompanyResource`.

## What Caused It
The error is triggered during the Inertia response rendering process when sharing the authenticated user inside `HandleInertiaRequests.php`.

Here is the exact chain of events:
1. In `HandleInertiaRequests.php`, the authenticated user is loaded with its `activeCompany` relationship, passed into `UserResource`, and `->resolve()` is immediately called on it.
2. Inside `App\Http\Resources\UserResource::toArray()`, there is the following code block:
   ```php
   'activeCompany' => $this->when('activeCompany', (new CompanyResource($this->activeCompany))->resolve()),
   ```
3. The first argument to the `$this->when()` method is the string `'activeCompany'`. In PHP, a non-empty string always evaluates to `true`. Therefore, this `when()` condition never fails.
4. For users who do not currently have an active company assigned, `$this->activeCompany` is `null`.
5. The code instantiates `new CompanyResource(null)` and immediately triggers `->resolve()`.
6. Inside `App\Http\Resources\CompanyResource::toArray()`, the code attempts to map `'id' => $this->id`. Since the underlying `$this->resource` is `null`, it throws the `Attempt to read property "id" on null` exception.

*Side Note: The same bug exists for your `roles` and `permissions` definitions in `UserResource`, as they also incorrectly use static strings (`'roles'`, `'permissions'`) as their condition.*

## Solutions

Choose one of the following solutions to update `app/Http/Resources/UserResource.php`.

### Solution 1: Use `whenLoaded` (Recommended Laravel Approach)
The cleanest "Laravel way" to handle conditionally loaded relationships (and automatically dropping them if they don't exist or are `null`) is to omit `->resolve()` and use `whenLoaded()`.
```php
'activeCompany' => new CompanyResource($this->whenLoaded('activeCompany')),
'roles' => RoleResource::collection($this->whenLoaded('roles')),
```
*Note: Since you are casting the root `UserResource` with `->resolve()` in your Middleware, Laravel will still automatically and recursively resolve these nested resources into arrays for Inertia.*

### Solution 2: Explicitly Check for Null Values
If you specifically want to manually call `->resolve()` to ensure arrays are returned, you must explicitly check if the relationship exists instead of wrapping it in `when()` with a static string.
```php
'activeCompany' => $this->activeCompany ? (new CompanyResource($this->activeCompany))->resolve() : null,
'roles' => $this->roles ? RoleResource::collection($this->roles)->resolve() : [],
'permissions' => $this->permissions ? PermissionResource::collection($this->getAllPermissions())->resolve() : [],
```

### Solution 3: Use a Proper Boolean Condition in `when()`
If you prefer to stick to the `when()` method, pass a strict boolean check or the object itself as the first argument, rather than a string.
```php
'activeCompany' => $this->when($this->activeCompany !== null, function () {
    return (new CompanyResource($this->activeCompany))->resolve();
}),
```

Applying any of these solutions will prevent the `CompanyResource` from executing when the user has no defined `activeCompany`, successfully fixing the 500 Server Error.
