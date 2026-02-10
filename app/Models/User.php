<?php

namespace App\Models;

use App\Traits\GlobalScopes\HasSearchScope;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use App\Traits\Permissions\HasRoles;

class User extends Authenticatable implements MustVerifyEmail
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasFactory, Notifiable, SoftDeletes, HasRoles, HasSearchScope;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'username',
        'phone',
        'email',
        'password',
        'profile_photo_path',
        'active_company_id',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    public function getRouteKeyName()
    {
        return 'username';
    }

    public function activeCompany()
    {
        return $this->belongsTo(Company::class, 'active_company_id');
    }

    public function ownedCompanies()
    {
        return $this->belongsToMany(Company::class, 'company_user')->using(CompanyUser::class)->where('company_user.role', 'owner');
    }

    public function companies()
    {
        return $this->belongsToMany(Company::class, 'company_user')->using(CompanyUser::class);
    }

    public function abilities()
    {
        return $this->belongsToMany(Ability::class, 'ability_assignments')->withPivot('company_id');
    }

    public function jobTitles()
    {
        return $this->belongsToMany(JobTitle::class, 'job_title_user', 'employee_id', 'job_title_id')->withPivot('company_id');
    }

    public function departments()
    {
        return $this->belongsToMany(Department::class, 'department_employee', 'employee_id', 'department_id')->withPivot('company_id');
    }
}