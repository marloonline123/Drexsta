<?php

namespace App\Traits\Permissions;

use App\Models\Permission;
use App\Resolver\PermissionResolver;
use App\Services\Permissions\RolePermissionService;
use App\Services\Permissions\UserPermissionService;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

trait HasPermissions
{
    protected function rolePermissionService(): RolePermissionService
    {
        return app(RolePermissionService::class);
    }

    protected function userPermissionService(): UserPermissionService
    {
        return app(UserPermissionService::class);
    }

    public function getPermissionsAttribute(?int $companyId = null)
    {
        return $this->getCachedPermissions($companyId);
    }

    public function directPermissions(): BelongsToMany
    {
        return $this->belongsToMany(Permission::class, 'permission_user', 'user_id', 'permission_id')->withPivot('company_id', 'authorize');
    }

    /**
     * Get all permission names for this user (direct + role-based) for the given company.
     */
    public function getCachedPermissions(?int $companyId = null): array
    {
        $companyId = $companyId ?? $this->active_company_id;
        $permissions = app(PermissionResolver::class)->resolve($this, $companyId)->toArray();

        Log::info("Get Cached Permissions");
        Log::debug($permissions);

        return $permissions;
    }

    /**
     * Get all Permission models for this user for the active company.
     * Used by resources (UserResource, EmployeeResource) for serialization.
     */
    public function getAllPermissions(?int $companyId = null): \Illuminate\Support\Collection
    {
        $names = $this->getCachedPermissions($companyId);

        return Permission::whereIn('name', $names)->get();
    }

    public function clearCachedPermissions(?int $companyId = null): void
    {
        $companyId = $companyId ?? $this->active_company_id;
        Cache::forget("user:{$this->id}:company:{$companyId}:permissions");
    }

    public function hasPermissionTo(string $permission, ?int $companyId = null): bool
    {
        $permissions = $this->getCachedPermissions($companyId);

        return in_array($permission, $permissions, true);
    }

    public function hasPermission(string $permission, ?int $companyId = null): bool
    {
        $permissions = $this->getCachedPermissions($companyId);

        return in_array($permission, $permissions, true);
    }

    public function hasAnyPermission(array $permissions, ?int $companyId = null): bool
    {
        $cachedPermissions = $this->getCachedPermissions($companyId);

        foreach ($permissions as $permission) {
            if (in_array($permission, $cachedPermissions, true)) {
                return true;
            }
        }

        return false;
    }

    public function give($permission, $companyId = null): void
    {
        $this->userPermissionService()->give($this, $permission, $companyId);
        $this->clearCachedPermissions($companyId);
    }

    public function revoke($permission, $companyId = null): void
    {
        $this->userPermissionService()->revoke($this, $permission, $companyId);
        $this->clearCachedPermissions($companyId);
    }

    public function sync($permissionsIds, $companyId = null): void
    {
        $this->userPermissionService()->sync($this, $permissionsIds, $companyId);
        $this->clearCachedPermissions($companyId);
    }
}

