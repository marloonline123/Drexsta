<?php

namespace App\Services\Permissions;

use App\Models\Role;
use App\Models\RoleUser;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class RoleAssignmentService
{
    public function hasRole(User $user, string|array $role, ?int $companyId = null): bool
    {
        if (is_array($role)) {
            return $this->hasAnyRole($user, $role, $companyId);
        }

        if ($companyId === null) {
            return $user->roles()
                ->where('name', $role)
                ->exists();
        }

        return $user->roles()
            ->where('name', $role)
            ->where('company_id', $companyId)
            ->exists();
    }

    public function hasAnyRole(User $user, array $roles, ?int $companyId = null): bool
    {
        if ($companyId === null) {
            return $user->roles()
                ->whereIn('name', $roles)
                ->exists();
        }

        return $user->roles()
            ->whereIn('name', $roles)
            ->where('company_id', $companyId)
            ->exists();
    }

    public function assign(User $user, Role|string|int $role, ?int $companyId = null): void
    {
        if (is_string($role)) {
            $role = Role::where('name', $role)->orWhere('id', $role)->first();
        }
        if (is_int($role)) {
            $role = Role::where('id', $role)->first();
        }
        if (! $role) {
            Log::error("Given Role: '{$role}' doesn't exist!");

            return;
        }
        RoleUser::firstOrCreate([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'company_id' => $companyId,
        ]);

        $user->clearCachedPermissions($companyId);
    }

    public function remove(User $user, Role $role, ?int $companyId = null): void
    {
        RoleUser::where([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'company_id' => $companyId,
        ])->delete();

        $user->clearCachedPermissions($companyId);
    }

    public function sync(User $user, array $roleIds, ?int $companyId = null): void
    {
        DB::transaction(function () use ($user, $roleIds, $companyId) {
            RoleUser::where('user_id', $user->id)
                ->where('company_id', $companyId)
                ->delete();

            foreach ($roleIds as $roleId) {
                RoleUser::create([
                    'user_id' => $user->id,
                    'role_id' => $roleId,
                    'company_id' => $companyId,
                ]);
            }
        });

        $user->clearCachedPermissions($companyId);
    }
}
