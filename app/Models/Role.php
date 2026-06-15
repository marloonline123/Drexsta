<?php

namespace App\Models;

use App\Traits\GlobalScopes\HasSearchScope;
use Spatie\Permission\Models\Role as SpatieRole;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Role extends SpatieRole
{
    use HasSearchScope;

    protected $fillable = [
        'name',
        'guard_name',
        'company_id',
    ];
    
    /**
     * Get the company that owns the role.
     */
    public function company(): BelongsTo
    {
        return $this->belongsTo(Company::class);
    }
}