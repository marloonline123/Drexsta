<?php

namespace App\Models;

use App\Traits\GlobalScopes\HasActiveScope;
use App\Traits\GlobalScopes\HasFilterByScope;
use App\Traits\GlobalScopes\HasSearchScope;
use App\Traits\HasCompanyScope;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

class JobTitle extends Model
{
    use HasCompanyScope,
        HasSearchScope,
        HasFilterByScope,
        HasActiveScope,
        SoftDeletes;

    protected static function booted(): void
    {
        // parent::booted();

        static::creating(function ($jobTitle) {
            $jobTitle->slug = generateUniqueSlug($jobTitle::class, $jobTitle->title);
        });
        static::updating(function ($jobTitle) {
            if ($jobTitle->isDirty('title')) {
                $jobTitle->slug = generateUniqueSlug($jobTitle::class, $jobTitle->title, $jobTitle->id);
            }
        });
    }

    protected $fillable = [
        'company_id',
        'title',
        'slug',
        'description',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'deleted_at' => 'datetime',
    ];

    /**
     * Relationships
     */
    public function company(): BelongsTo
    {
        return $this->belongsTo(Company::class);
    }
}
