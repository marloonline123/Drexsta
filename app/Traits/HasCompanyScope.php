<?php

namespace App\Traits;

use App\Scopes\CompanyScope;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;

trait HasCompanyScope
{
    /**
     * The "booted" method of the model.
     */
    protected static function bootHasCompanyScope(): void
    {
        static::addGlobalScope(new CompanyScope());

        static::creating(function (Model $model) {
            if (Auth::check() && Schema::hasColumn($model->getTable(), 'company_id')) {
                $model->company_id = $model->company_id ?? Auth::user()->active_company_id;
            }
        });
    }
}