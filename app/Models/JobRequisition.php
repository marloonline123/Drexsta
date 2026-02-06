<?php

namespace App\Models;

use App\Traits\GlobalScopes\HasFilterByScope;
use App\Traits\HasCompanyScope;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

class JobRequisition extends BaseModel
{
    use SoftDeletes, HasFilterByScope;

    protected $fillable = [
        'company_id',
        'department_id',
        'job_title_id',
        'requested_by',
        'requisition_code',
        'number_of_positions',
        'job_description',
        'requirements',
        'employment_type_id',
        'min_salary',
        'max_salary',
        'target_start_date',
        'status',
        'reason',
        'additional_notes',
    ];

    protected $casts = [
        'min_salary' => 'decimal:2',
        'max_salary' => 'decimal:2',
        'target_start_date' => 'date',
    ];

    public function scopeApproved($query)
    {
        return $query->where('status', 'approved');
    }

    public function company(): BelongsTo
    {
        return $this->belongsTo(Company::class);
    }

    public function department(): BelongsTo
    {
        return $this->belongsTo(Department::class);
    }

    public function jobTitle(): BelongsTo
    {
        return $this->belongsTo(JobTitle::class);
    }

    public function requester(): BelongsTo
    {
        return $this->belongsTo(User::class, 'requested_by');
    }

    public function employmentType(): BelongsTo
    {
        return $this->belongsTo(EmploymentType::class);
    }
}