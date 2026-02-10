<?php

namespace App\Services\Permissions;

use App\Models\Permission;
use App\Models\PermissionUser;
use App\Models\User;
use Illuminate\Support\Facades\DB;

class UserPermissionService
{
    public function give(User $user, int|string $permission, ?int $companyId = null): void
    {
        $permissionId = $permission;
        if (is_string($permission)) {
            $retrivedPermission = Permission::where('name', $permission)->first();
            if (!$retrivedPermission) {
                return;
            }
            $permissionId = $retrivedPermission->id;
        }
        PermissionUser::firstOrCreate([
            'user_id' => $user->id,
            'permission_id' => $permissionId,
            'company_id' => $companyId,
        ]);
    }

    public function revoke(User $user, Permission $permission, ?int $companyId = null): void
    {
        PermissionUser::where([
            'user_id' => $user->id,
            'permission_id' => $permission->id,
            'company_id' => $companyId,
        ])->delete();
    }

    public function sync(User $user, array $permissionIds, ?int $companyId = null): void
    {
        $user->clearCachedPermissions($companyId);

        // Resolve all string names to IDs and filter out invalid/duplicate ones
        $normalizedIds = [];
        foreach ($permissionIds as $id) {
            if (is_string($id)) {
                $permission = Permission::where('name', $id)->first();
                if ($permission) {
                    $normalizedIds[] = $permission->id;
                }
            } elseif (is_numeric($id)) {
                $normalizedIds[] = (int) $id;
            }
        }

        $normalizedIds = array_unique($normalizedIds);

        DB::transaction(function () use ($user, $normalizedIds, $companyId) {
            PermissionUser::where('user_id', $user->id)
                ->where('company_id', $companyId)
                ->delete();

            foreach ($normalizedIds as $permissionId) {
                PermissionUser::create([
                    'user_id' => $user->id,
                    'permission_id' => $permissionId,
                    'company_id' => $companyId,
                ]);
            }
        });
    }

    public function detachAllPermissions(User $user, ?int $companyId = null): void
    {
        $user->clearCachedPermissions($companyId);

        PermissionUser::where('user_id', $user->id)
            ->where('company_id', $companyId)
            ->delete();
    }
}
