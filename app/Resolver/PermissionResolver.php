<?php

namespace App\Resolver;

use App\Models\PermissionRole;
use App\Models\User;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;

class PermissionResolver
{
    public function resolve(User $user, ?int $companyId): Collection
    {
        return Cache::remember(
            "user:{$user->id}:company:{$companyId}:permissions",
            now()->addHour(),
            function () use ($user, $companyId) {

                // Direct user permissions scoped to company
                $directPermissions = $user->directPermissions()
                    ->wherePivot('company_id', $companyId)
                    ->get(['name', 'permission_user.authorize']);

                $directAuthorized = $directPermissions
                    ->where('pivot.authorize', true)
                    ->pluck('name');

                $directUnauthorized = $directPermissions
                    ->where('pivot.authorize', false)
                    ->pluck('name')
                    ->toArray();


                // Role permissions scoped to company via permission_role pivot
                $roleIds = $user->roles()
                    ->where('role_user.company_id', $companyId)
                    ->pluck('roles.id');

                $rolePermissions = PermissionRole::whereIn('role_id', $roleIds)
                    ->where('company_id', $companyId)
                    ->with('permission')
                    ->get()
                    ->pluck('permission.name')
                    ->filter();

                return $directAuthorized
                    ->merge($rolePermissions)
                    ->unique()
                    ->map(function ($permission) use ($directUnauthorized) {
                        if (! in_array($permission, $directUnauthorized)) {
                            return $permission;
                        }
                    });
            }
        );
    }
}

