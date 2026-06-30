<?php

namespace App\Traits\GlobalScopes;

use Illuminate\Database\Eloquent\Builder;

trait HasSearchScope
{
    /**
     * Scope a query to search for a specific value in the given columns.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $query
     * @param  string|null  $value
     * @param  array|string  $columns the default column is "name"
     * @return \Illuminate\Database\Eloquent\Builder
     */
    
    public function scopeSearch(Builder $query, string|null $value, array|string $columns = 'name'): Builder
    {
        if (empty($columns) || empty($value)) return $query;

        $columns = (array) $columns;

        return $query->whereAny($columns, 'LIKE', "%{$value}%");
    }
}