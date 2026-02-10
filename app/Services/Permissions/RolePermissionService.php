<?php

namespace App\Services\Permissions;

use App\Models\Permission;
use App\Models\PermissionRole;
use App\Models\Role;
use Illuminate\Support\Facades\DB;

class RolePermissionService
{
    public function give(Role $role, Permission $permission, ?int $companyId = null): void
    {
        PermissionRole::firstOrCreate([
            'role_id' => $role->id,
            'permission_id' => $permission->id,
            'company_id' => $companyId,
        ]);
    }

    public function revoke(Role $role, Permission $permission, ?int $companyId = null): void
    {
        PermissionRole::where([
            'role_id' => $role->id,
            'permission_id' => $permission->id,
            'company_id' => $companyId,
        ])->delete();
    }

    /**
     * Sync permissions for a role. Accepts an array of Permission models, IDs, or permission name strings.
     */
    public function sync(Role $role, array $permissions, ?int $companyId = null): void
    {
        $normalizedIds = $this->normalizePermissionIds($permissions);

        DB::transaction(function () use ($role, $normalizedIds, $companyId) {
            PermissionRole::where('role_id', $role->id)
                ->where('company_id', $companyId)
                ->delete();

            foreach ($normalizedIds as $permissionId) {
                PermissionRole::create([
                    'role_id' => $role->id,
                    'permission_id' => $permissionId,
                    'company_id' => $companyId,
                ]);
            }
        });
    }

    /**
     * Normalize mixed permission inputs (models, IDs, strings) to integer IDs.
     */
    private function normalizePermissionIds(array $permissions): array
    {
        $ids = [];

        foreach ($permissions as $permission) {
            if ($permission instanceof Permission) {
                $ids[] = $permission->id;
            } elseif (is_numeric($permission)) {
                $ids[] = (int) $permission;
            } elseif (is_string($permission)) {
                $found = Permission::where('name', $permission)->first();
                if ($found) {
                    $ids[] = $found->id;
                }
            }
        }

        return array_unique($ids);
    }
}

