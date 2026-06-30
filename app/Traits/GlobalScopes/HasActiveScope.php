<?php

namespace App\Traits\GlobalScopes;

use Illuminate\Database\Eloquent\Builder;

trait HasActiveScope
{
    /**
     * Scope a query to only include active records.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $query
     * @param  bool|null  $isActive the default value is true
     * @param  string  $column the default column is is_active
     * @return \Illuminate\Database\Eloquent\Builder
     */

    public function scopeActive(Builder $query, ?bool $isActive = true, string $column = 'is_active'): Builder
    {
        $isActive = boolval($isActive);
        if ($isActive === null) return $query;
        return $query->where($column, $isActive);
    }
}