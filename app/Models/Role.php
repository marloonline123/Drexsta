<?php

namespace App\Models;

use App\Services\Permissions\RolePermissionService;
use App\Traits\GlobalScopes\HasSearchScope;
use App\Traits\HasCompanyScope;
use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\Models\Role as SpatieRole;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Role extends Model
{
    use HasSearchScope, HasCompanyScope;

    protected $fillable = [
        'name',
        'description',
        'meta_data',
        'company_id',
    ];
    
    /**
     * Get the company that owns the role.
     */
    public function company(): BelongsTo
    {
        return $this->belongsTo(Company::class);
    }

    public function permissions()
    {
        return $this->belongsToMany(Permission::class, 'permission_role');
    }

    public function givePermissionTo(Permission $permission, ?int $companyId = null): void
    {
        $this->rolePermissionService()->give($this, $permission, $companyId);
    }

    public function revokePermissionTo(Permission $permission, ?int $companyId = null): void
    {
        $this->rolePermissionService()->revoke($this, $permission, $companyId);
    }

    public function syncPermissions(array $permissions, ?int $companyId = null): void
    {
        $this->rolePermissionService()->sync($this, $permissions, $companyId);
    }

    public function rolePermissionService(): RolePermissionService
    {
        return app(RolePermissionService::class);
    }
}