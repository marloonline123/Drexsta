<?php

namespace App\Providers;

use Illuminate\Auth\Access\Response;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Bridge Laravel's $user->can() to our custom permission system
        Gate::define('*', function ($user, $ability) {
            return $user->hasPermission($ability, $user->active_company_id);
        });
    }
}
