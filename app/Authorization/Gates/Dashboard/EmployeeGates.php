<?php

namespace App\Authorization\Gates\Dashboard;

use App\Models\User;
use Illuminate\Support\Facades\Gate;

class EmployeeGates
{
    public const GUARD = 'web';

    public static function register(): void
    {
        Gate::define('admin.employees.view', function (User $user): bool {
            return $user->hasPermissionTo('employees.view', self::GUARD);
        });

        Gate::define('admin.employees.create', function (User $user): bool {
            return $user->hasPermissionTo('employees.create', self::GUARD);
        });

        Gate::define('admin.employees.edit', function (User $user): bool {
            return $user->hasPermissionTo('employees.edit', self::GUARD);
        });

        Gate::define('admin.employees.delete', function (User $user): bool {
            return $user->hasPermissionTo('employees.delete', self::GUARD);
        });
    }
}
