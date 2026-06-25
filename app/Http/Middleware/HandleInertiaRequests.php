<?php

namespace App\Http\Middleware;

use App\Http\Resources\CompanyResource;
use App\Http\Resources\UserResource;
use Illuminate\Foundation\Inspiring;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
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
            'translations' => fn(): array => $this->getTranslations($request),
            'locale' => config('app.locale'),
        ];
    }

    /**
     * Load translations from lang/{locale}/ directory PHP files.
     */
    private function getTranslations(Request $request): array
    {
        // Priority: cookie > session > Accept-Language header > default 'en'
        $locale = config('app.locale')
            ?? $request->session()->get('locale')
            ?? (in_array(substr($request->header('Accept-Language', 'en'), 0, 2), ['en', 'ar'], true)
                ? substr($request->header('Accept-Language', 'en'), 0, 2)
                : 'en');

        // Validate locale to prevent directory traversal
        $allowedLocales = ['en', 'ar'];
        if (!in_array($locale, $allowedLocales, true)) {
            $locale = 'en';
        }

        $langPath = dirname(__DIR__, 3) . "/lang/{$locale}";

        Log::info("Loading translations from: {$langPath}");

        if (!is_dir($langPath)) {
            return [];
        }

        $translations = [];

        // Get all PHP files in the language directory
        $phpFiles = glob($langPath . '/*.php');

        foreach ($phpFiles as $file) {
            // Skip files that start with dot (like .gitignore)
            if (basename($file)[0] === '.') {
                continue;
            }
            
            // Extract the filename without extension to use as key
            $filename = basename($file, '.php');
            
            // Load the translation array from the PHP file
            $translationArray = require $file;
            
            // Merge the translation array into our main translations array
            // This preserves the nested structure expected by the frontend
            $translations[$filename] = $translationArray;
        }

        return $translations;
    }
}
