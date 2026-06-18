<?php

namespace App\Models;

use App\Enums\JobApplicationStatus;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

class JobApplication extends BaseModel
{
    use SoftDeletes;
    
    protected $fillable = [
        'company_id',
        'job_posting_id',
        'number',
        'name',
        'email',
        'phone',
        'cover_letter',
        'resume_path',
        'status',
        'application_token',
        'token_expires_at',
        'custom_fields',
    ];

    protected $casts = [
        'status' => JobApplicationStatus::class,
        'token_expires_at' => 'datetime',
        'custom_fields' => 'array',
    ];

    public function company(): BelongsTo
    {
        return $this->belongsTo(Company::class);
    }

    public function jobPosting(): BelongsTo
    {
        return $this->belongsTo(JobPosting::class);
    }

    /**
     * Check if the application can be edited.
     */
    public function canBeEdited(): bool
    {
        return $this->status !== JobApplicationStatus::UNDER_REVIEW && 
               $this->jobPosting->status !== \App\Enums\JobPostingStatus::CLOSED &&
               $this->token_expires_at && 
               $this->token_expires_at->isFuture();
    }

    /**
     * Generate a secure token for editing the application.
     */
    public function generateToken(): void
    {
        $this->application_token = bin2hex(random_bytes(32));
        $this->token_expires_at = now()->addDays(7); // Token valid for 7 days
        $this->save();
    }
}