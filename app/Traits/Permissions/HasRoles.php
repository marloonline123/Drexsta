<?php

namespace App\Traits\Permissions;

use App\Models\Role;
use App\Services\Permissions\RoleAssignmentService;

trait HasRoles
{
    use HasPermissions;
    
    protected function roleAssignmentService(): RoleAssignmentService
    {
        return app(RoleAssignmentService::class);
    }

    public function roles()
    {
        return $this->belongsToMany(Role::class, 'role_user', 'user_id', 'role_id');
    }

    public function hasRole(string|array $role, ?int $companyId = null): bool
    {
        return $this->roleAssignmentService()->hasRole($this, $role, $companyId);
    }

    public function hasAnyRole(array $roles, ?int $companyId = null): bool
    {
        return $this->roleAssignmentService()->hasAnyRole($this, $roles, $companyId);
    }

    public function syncRoles(array $roles, ?int $companyId = null): void
    {
        $this->roleAssignmentService()->sync($this, $roles, $companyId);
    }

    public function assignRole(Role|string|int $role, ?int $companyId = null): void
    {
        $this->roleAssignmentService()->assign($this, $role, $companyId);
    }
}
