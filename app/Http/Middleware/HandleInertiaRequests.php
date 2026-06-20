<?php

namespace App\Http\Middleware;

use App\Http\Resources\CompanyResource;
use App\Http\Resources\UserResource;
use Illuminate\Foundation\Inspiring;
use Illuminate\Http\Request;
use Inertia\Middleware;
use Tighten\Ziggy\Ziggy;

class HandleInertiaRequests extends Middleware
{
    /**
     * The root template that's loaded on the first page visit.
     *
     * @see https://inertiajs.com/server-side-setup#root-template
     *
     * @var string
     */
    protected $rootView = 'app';

    /**
     * Determines the current asset version.
     *
     * @see https://inertiajs.com/asset-versioning
     */
    public function version(Request $request): ?string
    {
        return parent::version($request);
    }

    /**
     * Define the props that are shared by default.
     *
     * @see https://inertiajs.com/shared-data
     *
     * @return array<string, mixed>
     */
    public function share(Request $request): array
    {
        [$message, $author] = str(Inspiring::quotes()->random())->explode('-');
        $user = $request->user();

        return [
            ...parent::share($request),
            'name' => config('app.name'),
            'quote' => ['message' => trim($message), 'author' => trim($author)],
            'auth' => [
                'user' => $user ? (new UserResource($user->load('activeCompany', 'roles', 'permissions')))->resolve() : null,
            ],
            'ziggy' => fn(): array => [
                ...(new Ziggy)->toArray(),
                'location' => $request->url(),
            ],
            'flash' => [
                'success' => fn(): ?string => $request->session()->get('success'),
                'error' => fn(): ?string => $request->session()->get('error'),
            ],
            'sidebarCompanies' => fn(): array => $request->user() ? CompanyResource::collection($request->user()->companies()->with('users')->get())->resolve() : [],
            'sidebarOpen' => !$request->hasCookie('sidebar_state') || $request->cookie('sidebar_state') === 'true',
            'translation' => fn(): array => $this->getTranslations($request),
        ];
    }

    /**
     * Load translations from lang/{locale}.json file.
     */
    private function getTranslations(Request $request): array
    {
        // Priority: cookie > session > Accept-Language header > default 'en'
        $locale = $request->cookie('language')
            ?? $request->session()->get('language')
            ?? (in_array(substr($request->header('Accept-Language', 'en'), 0, 2), ['en', 'ar'], true)
                ? substr($request->header('Accept-Language', 'en'), 0, 2)
                : 'en');

        // Validate locale to prevent directory traversal
        $allowedLocales = ['en', 'ar'];
        if (!in_array($locale, $allowedLocales, true)) {
            $locale = 'en';
        }

        $path = resource_path("lang/{$locale}.json");

        if (!file_exists($path)) {
            return [];
        }

        return json_decode(file_get_contents($path), true) ?? [];
    }
}
