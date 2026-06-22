# Gate Authorization Implementation Guide

This document describes how **Laravel Gates** are implemented and used throughout the codebase for admin authorization, replacing the traditional Policy-based approach.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Gate Definition Layer](#gate-definition-layer)
  - [GateRegistrar – Central Registry](#gateregistrar--central-registry)
  - [VendorGates – Vendor Permission Gates](#vendorgates--vendor-permission-gates)
  - [TenantGates – Tenant Permission Gates](#tenantgates--tenant-permission-gates)
- [Registration (Boot Phase)](#registration-boot-phase)
- [Usage in Controllers](#usage-in-controllers)
  - [VendorController](#vendorcontroller)
  - [TenantController](#tenantcontroller)
- [Usage in Form Requests](#usage-in-form-requests)
  - [CreateTenantRequest](#createtenantrequest)
  - [UpdateTenantRequest](#updatetenantrequest)
  - [UpdateVendorRequest](#updatevendorrequest)
- [Naming Convention](#naming-convention)
- [Why Gates Instead of Policies](#why-gates-instead-of-policies)
- [Adding New Gates (Developer Guide)](#adding-new-gates-developer-guide)

---

## Architecture Overview

```
AppServiceProvider::boot()
        │
        ▼
GateRegistrar::register()
        │
        ├──▶ VendorGates::register()   ──▶ Gate::define('admin.vendors.*')
        └──▶ TenantGates::register()   ──▶ Gate::define('admin.tenants.*')
                                                │
                        ┌────────────────────────┼─────────────────────┐
                        ▼                        ▼                     ▼
              Controllers             Form Requests             Blade / Inertia
        $this->authorize()         Gate::allows()            @can / can()
```

The flow:
1. During app boot, `AppServiceProvider` calls `GateRegistrar::register()`.
2. `GateRegistrar` iterates over all registered Gate classes and calls their static `register()` method.
3. Each Gate class uses `Gate::define()` to register closures that delegate to **Spatie Permission** (`hasPermissionTo`).
4. Gates are consumed in controllers via `$this->authorize()`, in form requests via `Gate::allows()`, and optionally in views.

---

## Gate Definition Layer

### GateRegistrar – Central Registry

The `GateRegistrar` is the single entry point that bootstraps all gate classes. It lives in `app/Authorization/Gates/GateRegistrar.php`.

```php
<?php

namespace App\Authorization\Gates;

class GateRegistrar
{
    public static function register(): void
    {
        foreach ([
            \App\Authorization\Gates\Admin\VendorGates::class,
            \App\Authorization\Gates\Admin\TenantGates::class,
        ] as $class) {
            $class::register();
        }
    }
}
```

**Key design decisions:**
- Static method — no instantiation needed; called once at boot.
- Array-driven — adding a new Gate class only requires appending its FQCN to the array.
- Each Gate class must expose a static `register()` method.

---

### VendorGates – Vendor Permission Gates

Lives in `app/Authorization/Gates/Admin/VendorGates.php`.

```php
<?php

namespace App\Authorization\Gates\Admin;

use App\Models\User;
use Illuminate\Support\Facades\Gate;

class VendorGates
{
    public const GUARD = 'web';

    public static function register(): void
    {
        Gate::define('admin.vendors.view', function (User $user): bool {
            return $user->hasPermissionTo('vendors.view', self::GUARD);
        });

        Gate::define('admin.vendors.create', function (User $user): bool {
            return $user->hasPermissionTo('vendors.create', self::GUARD);
        });

        Gate::define('admin.vendors.edit', function (User $user): bool {
            return $user->hasPermissionTo('vendors.edit', self::GUARD);
        });

        Gate::define('admin.vendors.delete', function (User $user): bool {
            return $user->hasPermissionTo('vendors.delete', self::GUARD);
        });
    }
}
```

---

### TenantGates – Tenant Permission Gates

Lives in `app/Authorization/Gates/Admin/TenantGates.php`.

```php
<?php

namespace App\Authorization\Gates\Admin;

use App\Models\User;
use Illuminate\Support\Facades\Gate;

class TenantGates
{
    public const GUARD = 'web';

    public static function register(): void
    {
        Gate::define('admin.tenants.view', function (User $user): bool {
            return $user->hasPermissionTo('tenants.view', self::GUARD);
        });

        Gate::define('admin.tenants.create', function (User $user): bool {
            return $user->hasPermissionTo('tenants.create', self::GUARD);
        });

        Gate::define('admin.tenants.edit', function (User $user): bool {
            return $user->hasPermissionTo('tenants.edit', self::GUARD);
        });

        Gate::define('admin.tenants.delete', function (User $user): bool {
            return $user->hasPermissionTo('tenants.delete', self::GUARD);
        });
    }
}
```

---

## Registration (Boot Phase)

The `AppServiceProvider` triggers registration during the Laravel boot lifecycle. Lives in `app/Providers/AppServiceProvider.php`.

```php
<?php

namespace App\Providers;

use App\Authorization\AdminGates;
use App\Authorization\Gates\GateRegistrar;
use Carbon\CarbonImmutable;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\ServiceProvider;
use Illuminate\Validation\Rules\Password;
use Laravel\Fortify\Contracts\RegisterResponse;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // $this->app->instance(RegisterResponse::class, new class implements RegisterResponse {
        //     public function toResponse($request)
        //     {
        //         return redirect()->route('orphan.dashboard');
        //     }
        // });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        JsonResource::withoutWrapping();
        $this->configureDefaults();
        GateRegistrar::register();   // ◀── All gates are registered here
    }

    /**
     * Configure default behaviors for production-ready applications.
     */
    protected function configureDefaults(): void
    {
        Date::use(CarbonImmutable::class);

        DB::prohibitDestructiveCommands(
            app()->isProduction(),
        );

        Password::defaults(
            fn(): ?Password => app()->isProduction()
                ? Password::min(12)
                ->mixedCase()
                ->letters()
                ->numbers()
                ->symbols()
                ->uncompromised()
                : null,
        );
    }
}
```

---

## Usage in Controllers

Gates are consumed in controllers via the `AuthorizesRequests` trait's `$this->authorize()` method. If the gate denies access, a `403 AuthorizationException` is thrown automatically.

### VendorController

Lives in `app/Http/Controllers/Admin/VendorController.php`.

```php
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Requests\Admin\Vendor\CreateVendorRequest;
use App\Http\Requests\Admin\Vendor\UpdateVendorRequest;
use App\Http\Resources\Admin\Vendor\VendorResource;
use App\Models\User;
use App\Policies\VendorPolicy;
use App\Services\Vendor\VendorService;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\Request;

class VendorController extends Controller
{
    use AuthorizesRequests;

    public function __construct(protected VendorService $vendorService) {}

    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $this->authorize('admin.vendors.view');   // ◀── Gate check

        $vendors = User::vendors()->paginate(20);

        return inertia('admin/vendors/index', [
            'vendors' => VendorResource::collection($vendors),
        ]);
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        $this->authorize('admin.vendors.create');  // ◀── Gate check

        return inertia('admin/vendors/create');
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(CreateVendorRequest $request)
    {
        $vendor = $this->vendorService->createVendor($request->validated());

        return to_route('admin.vendors.show', $vendor);
    }

    /**
     * Display the specified resource.
     */
    public function show(User $vendor)
    {
        $this->authorize('admin.vendors.view');   // ◀── Gate check

        return inertia('admin/vendors/show', [
            'vendor' => $vendor
        ]);
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(User $vendor)
    {
        $this->authorize('admin.vendors.edit');   // ◀── Gate check

        return inertia('admin/vendors/edit', [
            'vendor' => VendorResource::make($vendor)
        ]);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(UpdateVendorRequest $request, User $vendor)
    {
        $data = $request->validated();
        if ($request->has('password') && empty($request->input('password'))) {
            unset($data['password']);
        }
        $vendor = $this->vendorService->updateVendor($vendor, $data);

        return to_route('admin.vendors.show', $vendor);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(User $vendor)
    {
        $this->authorize('admin.vendors.delete');  // ◀── Gate check

        $vendor->delete();

        return to_route('admin.vendors.index');
    }
}
```

---

### TenantController

Lives in `app/Http/Controllers/Admin/TenantController.php`.

```php
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Requests\Admin\Tenant\CreateTenantRequest;
use App\Http\Requests\Admin\Tenant\UpdateTenantRequest;
use App\Http\Resources\Admin\Tenant\TenantResource;
use App\Models\Tenant;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;

class TenantController extends Controller
{
    use AuthorizesRequests;

    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $this->authorize('admin.tenants.view');   // ◀── Gate check

        $tenants = Tenant::with('owner')->paginate(20);

        return inertia('admin/tenants/index', [
            'tenants' => TenantResource::collection($tenants),
        ]);
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        $this->authorize('admin.tenants.create');  // ◀── Gate check

        $owners = 
            \App\Models\User::vendors()
                ->whereNotIn('id', Tenant::select('owner_id'))
                ->orderBy('name')
                ->get(['id', 'name']);

        return inertia('admin/tenants/create', [
            'owners' => $owners,
        ]);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(CreateTenantRequest $request)
    {
        $tenant = Tenant::create($request->validated());
        $tenant->users()->syncWithoutDetaching([$tenant->owner_id]);

        return to_route('admin.tenants.show', $tenant->getKey());
    }

    /**
     * Display the specified resource.
     */
    public function show(Tenant $tenant)
    {
        $this->authorize('admin.tenants.view');   // ◀── Gate check

        return inertia('admin/tenants/show', [
            'tenant' => $tenant,
        ]);
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(Tenant $tenant)
    {
        $this->authorize('admin.tenants.edit');   // ◀── Gate check

        return inertia('admin/tenants/edit', [
            'tenant' => TenantResource::make($tenant->load('owner')),
        ]);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(UpdateTenantRequest $request, Tenant $tenant)
    {
        $tenant->update($request->validated());

        return to_route('admin.tenants.show', $tenant->getKey());
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Tenant $tenant)
    {
        $this->authorize('admin.tenants.delete');  // ◀── Gate check

        Tenant::destroy($tenant->getKey());

        return to_route('admin.tenants.index');
    }
}
```

---

## Usage in Form Requests

Form requests use `Gate::allows()` inside the `authorize()` method. This provides a second layer of authorization at the request-validation level.

### CreateTenantRequest

Lives in `app/Http/Requests/Admin/Tenant/CreateTenantRequest.php`.

```php
<?php

namespace App\Http\Requests\Admin\Tenant;

use App\Enums\UserType;
use App\Models\Tenant;
use App\Models\User;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

class CreateTenantRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('admin.tenants.create');  // ◀── Gate check
    }

    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:50'],
            'owner_id' => [
                'required',
                'integer',
                Rule::exists('users', 'id')->where(function ($query) {
                    $query->where(function ($query) {
                        $query->whereHas('roles', function ($query) {
                            $query->where('name', 'vendor');
                        })->orWhereNotIn('type', [UserType::PLATFORM_ADMIN, UserType::PLATFORM_STAFF]);
                    });
                    $query->whereNotIn('id', Tenant::select('owner_id'));
                }),
            ],
        ];
    }
}
```

---

### UpdateTenantRequest

Lives in `app/Http/Requests/Admin/Tenant/UpdateTenantRequest.php`.

```php
<?php

namespace App\Http\Requests\Admin\Tenant;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

class UpdateTenantRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('admin.tenants.edit');  // ◀── Gate check
    }

    public function rules(): array
    {
        $tenant = $this->route('tenant');

        return [
            'name' => [
                'required',
                'string',
                'max:50',
                Rule::unique('tenants', 'name')->ignore($tenant?->id),
            ],
            'owner_id' => ['required', 'integer', Rule::exists('users', 'id')],
        ];
    }
}
```

---

### UpdateVendorRequest

Lives in `app/Http/Requests/Admin/Vendor/UpdateVendorRequest.php`.

```php
<?php

namespace App\Http\Requests\Admin\Vendor;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;

class UpdateVendorRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return Gate::allows('admin.vendors.edit');  // ◀── Gate check
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        $vendor = $this->route('vendor');

        return [
            'name' => ['required', 'string', 'max:50'],
            'email' => [
                'required',
                'email',
                Rule::unique('users', 'email')->ignore($vendor?->id),
            ],
            'password' => ['nullable', 'string', Password::default(), 'confirmed'],
        ];
    }
}
```

---

## Naming Convention

All gate abilities follow a strict dot-notation pattern:

```
admin.{resource}.{action}
```

| Gate Ability | Permission (Spatie) | Description |
|---|---|---|
| `admin.vendors.view` | `vendors.view` | View vendor list or detail |
| `admin.vendors.create` | `vendors.create` | Access create vendor form / submit |
| `admin.vendors.edit` | `vendors.edit` | Access edit vendor form / submit |
| `admin.vendors.delete` | `vendors.delete` | Delete a vendor |
| `admin.tenants.view` | `tenants.view` | View tenant list or detail |
| `admin.tenants.create` | `tenants.create` | Access create tenant form / submit |
| `admin.tenants.edit` | `tenants.edit` | Access edit tenant form / submit |
| `admin.tenants.delete` | `tenants.delete` | Delete a tenant |

The `admin.` prefix namespaces the gate to the admin panel, preventing collisions with gates that may be defined in other parts of the application (e.g., vendor-facing or tenant-facing features).

---

## Why Gates Instead of Policies

| Aspect | Gates (this codebase) | Policies |
|---|---|---|
| **Authorization basis** | Permission string via Spatie (`hasPermissionTo`) | Model instance relationship (ownership, etc.) |
| **Scope** | Resource-level — same rule for all instances | Instance-level — rule varies per model instance |
| **Registration** | Explicit, centralized in Gate classes | Auto-discovered by Laravel naming convention |
| **Best suited for** | Admin panels where access depends on assigned role permissions | User-facing features where ownership matters (e.g., "can user edit *their own* post?") |
| **Dependency** | Requires Spatie permissions to be seeded and assigned | Requires model to be passed to policy method |

In this codebase, admin authorization is purely **permission-based** — it doesn't matter *which* vendor or tenant record is being accessed, only whether the authenticated admin has the relevant permission. This makes Gates a natural fit over Policies.

---

## Adding New Gates (Developer Guide)

To add a new resource gate (e.g., `admin.coupons.*`):

**Step 1 — Create the Gate class** in `app/Authorization/Gates/Admin/`:

```php
<?php

namespace App\Authorization\Gates\Admin;

use App\Models\User;
use Illuminate\Support\Facades\Gate;

class CouponGates
{
    public const GUARD = 'web';

    public static function register(): void
    {
        Gate::define('admin.coupons.view', function (User $user): bool {
            return $user->hasPermissionTo('coupons.view', self::GUARD);
        });

        Gate::define('admin.coupons.create', function (User $user): bool {
            return $user->hasPermissionTo('coupons.create', self::GUARD);
        });

        Gate::define('admin.coupons.edit', function (User $user): bool {
            return $user->hasPermissionTo('coupons.edit', self::GUARD);
        });

        Gate::define('admin.coupons.delete', function (User $user): bool {
            return $user->hasPermissionTo('coupons.delete', self::GUARD);
        });
    }
}
```

**Step 2 — Register it** in `GateRegistrar`:

```php
foreach ([
    \App\Authorization\Gates\Admin\VendorGates::class,
    \App\Authorization\Gates\Admin\TenantGates::class,
    \App\Authorization\Gates\Admin\CouponGates::class,  // ◀── Add here
] as $class) {
    $class::register();
}
```

**Step 3 — Seed the Spatie permissions** in your seeder:

```php
Permission::create(['name' => 'coupons.view',   'guard_name' => 'web']);
Permission::create(['name' => 'coupons.create', 'guard_name' => 'web']);
Permission::create(['name' => 'coupons.edit',   'guard_name' => 'web']);
Permission::create(['name' => 'coupons.delete', 'guard_name' => 'web']);
```

**Step 4 — Use in your controller:**

```php
$this->authorize('admin.coupons.view');
```
