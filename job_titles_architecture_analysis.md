# Job Titles Section — Architecture & Design Analysis

> **Scope**: Full-stack analysis of the Job Titles module  
> **Reviewed By**: Senior Engineer Audit  
> **Date**: 2026-06-28  

---

## Files Analyzed

### Backend
| Layer | File |
|---|---|
| Controller | [JobTitleController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/Dashboard/JobTitleController.php) |
| Model | [JobTitle.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Models/JobTitle.php) |
| Base Model | [BaseModel.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Models/BaseModel.php) |
| Policy | [JobTitlePolicy.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Policies/JobTitlePolicy.php) |
| Form Request | [JobTitleRequest.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Requests/JobTitleRequest.php) |
| API Resource | [JobTitleResource.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Resources/JobTitleResource.php) |
| Global Scope | [CompanyScope.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Scopes/CompanyScope.php) |
| Traits | [HasCompanyScope.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Traits/HasCompanyScope.php), [HasSearchScope.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Traits/GlobalScopes/HasSearchScope.php), [HasFilterByScope.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Traits/GlobalScopes/HasFilterByScope.php) |
| Validation Rule | [UniqueScoped.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Rules/UniqueScoped.php) |
| Helper | [SlugHelper.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Helpers/SlugHelper.php) |
| Toggle Controller | [ToggleIsActiveController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/ToggleIsActiveController.php) |
| Employee Actions | [EmployeeActionsController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/Dashboard/Employee/EmployeeActionsController.php) |
| Pivot Models | [EmployeeJobTitle.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Models/EmployeeJobTitle.php), [JobTitleUser.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Models/JobTitleUser.php) |
| Migration | [create_job_titles_table.php](file:///d:/Projects/Portfolio/Drexsta-old/database/migrations/2025_09_03_130053_create_job_titles_table.php) |
| Translations | [en/job_titles.php](file:///d:/Projects/Portfolio/Drexsta-old/lang/en/job_titles.php), [ar/job_titles.php](file:///d:/Projects/Portfolio/Drexsta-old/lang/ar/job_titles.php) |
| Routes | [web.php](file:///d:/Projects/Portfolio/Drexsta-old/routes/web.php) (lines 64–69) |

### Frontend
| Layer | File |
|---|---|
| Page | [Index.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Pages/Dashboard/JobTitles/Index.tsx) |
| Page | [AssignJobTitles.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Pages/Dashboard/Employees/AssignJobTitles.tsx) |
| Component | [JobTitlesList.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/JobTitlesList.tsx) |
| Component | [CreateJobTitleModal.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/CreateJobTitleModal.tsx) |
| Component | [EditJobTitleModal.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/EditJobTitleModal.tsx) |
| Component | [ViewJobTitleModal.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/ViewJobTitleModal.tsx) |
| Component | [DeleteJobTitleModal.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/DeleteJobTitleModal.tsx) |
| Component | [JobTitleForm.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/JobTitleForm.tsx) |
| Types | [job-titles.ts](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Types/job-titles.ts) |

---

## 1. SOLID Principles Violations

### 1.1 Single Responsibility Principle (SRP)

#### Finding S1: Controller Contains Business Logic
**File**: [JobTitleController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/Dashboard/JobTitleController.php)  
**Severity**: 🔴 High  
**Lines**: 29–37, 50–52

The controller directly handles:
- Query building (search, filter, sort, paginate)
- Slug generation (`$data['slug'] = generateSlug($data['title'])`)
- Total count computation (`$company?->jobTitles()->count()`)
- Meta data assembly

```php
// Line 29-33: Query building directly in controller
$jobTitles = JobTitle::search($request->get('search'), ['title', 'description'])
    ->filterBy('is_active', ...)
    ->latest()
    ->paginate(12)
    ->withQueryString() ?? [];

// Line 51: Slug generation is business logic in controller
$data['slug'] = generateSlug($data['title']);
```

**Recommendation**: Extract a `JobTitleService` (or use a Query/Action class pattern) so the controller only orchestrates HTTP concerns. The slug generation should be handled at the model level via a `creating` Eloquent event or a `HasSlug` trait.

---

#### Finding S2: ToggleIsActiveController Uses Route Defaults for Model Resolution
**File**: [ToggleIsActiveController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/ToggleIsActiveController.php)  
**Severity**: 🟡 Medium

The controller dynamically resolves the model class from route defaults (`$request->route('resource_model')`), then does `$modelClass::findOrFail($id)`. This single-action controller simultaneously handles toggle logic for **every** entity type (departments, employment types, job titles), violating SRP by being a catch-all.

```php
// Line 15-18: Dynamic model resolution — zero type safety
$modelClass = $request->route('resource_model');
$id = collect($request->route()->parameters())->first();
$model = $modelClass::findOrFail($id);
```

**Recommendation**: While the DRY intent is valid, this approach lacks authorization checks for the specific model. At minimum, add policy authorization per model. Consider a trait-based approach (`HasToggleableStatus`) that each controller can use.

---

#### Finding S3: EmployeeActionsController Is a God Controller
**File**: [EmployeeActionsController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/Dashboard/Employee/EmployeeActionsController.php)  
**Severity**: 🟡 Medium

This single controller manages assignment of roles, abilities, departments, **and** job titles — four distinct domains. Each group of show/assign methods should be in its own controller or at minimum its own Action class.

---

### 1.2 Open/Closed Principle (OCP)

#### Finding O1: Hardcoded Pagination Size
**File**: [JobTitleController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/Dashboard/JobTitleController.php#L32)  
**Severity**: 🟢 Low

```php
->paginate(12)
```

Pagination size is hardcoded. If you ever need to support different page sizes (e.g., for API consumers or admin views), you'd have to modify this method.

**Recommendation**: Accept `per_page` from the request with a default and max cap:
```php
->paginate(min($request->integer('per_page', 12), 50))
```

---

### 1.3 Liskov Substitution Principle (LSP)

#### Finding L1: Duplicate Pivot Models for the Same Relationship
**Files**: [EmployeeJobTitle.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Models/EmployeeJobTitle.php), [JobTitleUser.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Models/JobTitleUser.php)  
**Severity**: 🔴 High

Two pivot models exist for what appears to be the same (or very similar) many-to-many relationship between users and job titles:
- `EmployeeJobTitle` → table `employee_job_title` (empty model, no `$fillable`, no relationships)
- `JobTitleUser` → table `job_title_user` (has `$fillable` and relationships)

The `User` model references `job_title_user` table, while `EmployeeJobTitle` references `employee_job_title`. This is either a dead model or a data integrity split.

**Recommendation**: Consolidate into a single pivot model (`JobTitleUser` extending `Pivot`) and remove the orphaned `EmployeeJobTitle` if unused.

---

### 1.4 Interface Segregation Principle (ISP)

#### Finding I1: JobTitleRequest Used for Both Create and Update
**File**: [JobTitleRequest.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Requests/JobTitleRequest.php)  
**Severity**: 🟡 Medium

A single form request handles both store and update validation. While the `UniqueScoped` rule does use `->except()` for updates, this couples creation-specific logic (e.g., slug generation expectations) with update-specific logic.

```php
// Line 34: Conditional except for updates
(new UniqueScoped(...))->except($this->job_title?->id ?? 0)
```

The `->except(0)` fallback when creating is a code smell — it works but is non-obvious.

**Recommendation**: Split into `StoreJobTitleRequest` and `UpdateJobTitleRequest` for clarity. Or, use `$this->isMethod('POST')` branching within a single request class for the divergent rules.

---

### 1.5 Dependency Inversion Principle (DIP)

#### Finding D1: Global Helper Function Instead of Injectable Service
**File**: [SlugHelper.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Helpers/SlugHelper.php)  
**Severity**: 🟡 Medium

`generateSlug()` is a global function rather than a method on an injectable service or a model trait. This makes it:
- Untestable in isolation (no mock/stub possible)
- Impossible to swap slug strategy per entity

```php
// Called directly in controller
$data['slug'] = generateSlug($data['title']);
```

**Recommendation**: Convert to a `SlugService` or better yet a `HasSlug` trait on the model:
```php
trait HasSlug {
    public static function bootHasSlug() {
        static::creating(fn ($model) => $model->slug = $model->slug ?? Str::slug($model->title ?? $model->name));
    }
}
```

---

## 2. Missing Design Patterns

### 2.1 Service Layer Pattern — Not Implemented
**Severity**: 🔴 High

There is **no** `JobTitleService` class. The `app/Services/` directory exists with `Business/`, `Permissions/`, `Shared/`, and `Storage/` subdirectories, yet job title business logic lives entirely in the controller. Other modules like abilities already use the service pattern (`AbilityService`).

**What a JobTitleService should encapsulate**:
- Creating a job title (slug generation + model creation)
- Updating (slug regeneration if title changes)
- Bulk operations (import/export)
- Stats computation (total, active, inactive counts)

---

### 2.2 Repository Pattern — Not Implemented
**Severity**: 🟢 Low (acceptable for this app size)

Eloquent queries are built inline in the controller. For this application's complexity level, a full repository pattern would be over-engineering. However, the query-building logic in the `index()` method should at minimum move to a scoped query method or a dedicated Query Builder class.

---

### 2.3 Data Transfer Object (DTO) Pattern — Not Implemented
**Severity**: 🟢 Low

The controller passes raw validated arrays directly to `JobTitle::create($data)`. A DTO (e.g., `JobTitleData`) would provide type safety and make the contract between controller and service explicit. This is a "nice-to-have" that pays off as the application grows.

---

### 2.4 Factory Pattern for Tests — Missing
**Severity**: 🔴 High

No `JobTitleFactory` exists in `database/factories/`. Without a factory:
- Feature tests require manual record creation
- Seeding logic is duplicated (see `OrganizationSeeder`)
- Fuzz/property-based testing is impossible

---

### 2.5 Observer Pattern — Not Used for Side Effects
**Severity**: 🟡 Medium

Slug generation happens manually in the controller. If a job title is created via a seeder, artisan command, or future API endpoint, the slug generation is bypassed (the `OrganizationSeeder` uses `Str::slug()` directly — a different slug algorithm than `generateSlug()`).

**Recommendation**: Use a model observer or `creating`/`updating` events:
```php
class JobTitleObserver {
    public function creating(JobTitle $jobTitle) {
        $jobTitle->slug = $jobTitle->slug ?? generateSlug($jobTitle->title);
    }
}
```

---

## 3. Performance Bottlenecks (1M req/min Scale)

### 3.1 Missing Database Indexes for Search
**Severity**: 🔴 Critical  
**File**: [create_job_titles_table.php](file:///d:/Projects/Portfolio/Drexsta-old/database/migrations/2025_09_03_130053_create_job_titles_table.php)

The `HasSearchScope` trait runs:
```sql
WHERE title LIKE '%search_term%' OR description LIKE '%search_term%'
```

At 1M req/min, these unindexed `LIKE '%...'` queries will cause full table scans on every request. The `description` column is `TEXT` type, making it even worse.

**Recommendation**:
1. Add a composite index: `$table->index(['company_id', 'is_active', 'title'])` for filtered listing
2. For search: implement MySQL full-text index on `(title, description)` or use a dedicated search service (Meilisearch/Algolia via Laravel Scout)
3. Add an index on `is_active` for the filter queries

---

### 3.2 N+1 Query on Total Count
**Severity**: 🟡 Medium  
**File**: [JobTitleController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/Dashboard/JobTitleController.php#L35)

```php
$totalJobTitles = $company?->jobTitles()->count() ?? 0;
```

This fires a **separate** `SELECT COUNT(*)` query on every page load, in addition to the paginated query. At 1M req/min, this doubles the database load.

**Recommendation**: Use the paginator's built-in `total()` or use `withCount()` on the company.

---

### 3.3 CompanyScope Is Commented Out — Data Leaks
**Severity**: 🔴 Critical  
**File**: [CompanyScope.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Scopes/CompanyScope.php#L17-L19)

```php
public function apply(Builder $builder, Model $model): void
{
    // if (Auth::check() && ($companyId = Auth::user()->active_company_id)) {
    //     $builder->where($model->qualifyColumn('company_id'), '=', $companyId);
    // }
}
```

The entire company scoping logic is **commented out**. This means every `JobTitle::query()` returns **all job titles across all companies**. This is simultaneously:
- A **security vulnerability** (multi-tenant data leak)
- A **performance killer** (queries return far more data than needed)

**Recommendation**: Uncomment and test the scope, or implement company scoping via middleware/query-level filtering. This is the single highest-priority fix.

---

### 3.4 No Query-Level Caching
**Severity**: 🟡 Medium

The index endpoint queries the database on every request. For relatively static data like job titles, a short-lived cache (60–300 seconds) with tag-based invalidation would dramatically reduce database load.

**Recommendation**:
```php
Cache::tags(['company:' . $companyId, 'job-titles'])
    ->remember('job-titles:list:' . md5($request->fullUrl()), 300, fn() => /* query */);
```

Invalidate on create/update/delete.

---

### 3.5 No Rate Limiting on CRUD Endpoints
**Severity**: 🟡 Medium  
**File**: [web.php](file:///d:/Projects/Portfolio/Drexsta-old/routes/web.php#L69)

The toggle-status route has `throttle:regular`, but the `apiResource` routes (store, update, destroy) have **no rate limiting**. A malicious or buggy client could flood the create endpoint.

**Recommendation**: Add `->middleware('throttle:regular')` to the apiResource route group, or use Laravel's per-user throttling.

---

### 3.6 Slug Uniqueness Not Enforced at Application Level
**Severity**: 🟡 Medium  
**File**: [JobTitleController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/Dashboard/JobTitleController.php#L51)

```php
$data['slug'] = generateSlug($data['title']);
```

If two requests with the same title arrive simultaneously, a race condition creates duplicate slugs. The database has a unique constraint (`company_id`, `slug`), so one request will fail with an unhandled `QueryException`.

**Recommendation**: Use `uniqueSlug()` (which already exists in the helper) instead of `generateSlug()`, and wrap creation in a transaction with a retry mechanism. Or use the `HasSlug` trait approach with automatic conflict resolution.

---

## 4. Senior Engineering Best Practices — Gaps

### 4.1 Translation Key Inconsistency
**Severity**: 🟡 Medium  
**Files**: Multiple frontend components

Translation keys are inconsistent between dot-notation formats:

| Component | Uses |
|---|---|
| [Index.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Pages/Dashboard/JobTitles/Index.tsx#L34) | `job_titles.title` (underscore) ✅ |
| [JobTitlesList.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/JobTitlesList.tsx#L96) | `jobTitles.empty.title` (camelCase) ❌ |
| [EditJobTitleModal.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/EditJobTitleModal.tsx#L18) | `jobTitles.modals.edit.description` (camelCase) ❌ |
| [ViewJobTitleModal.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/ViewJobTitleModal.tsx#L21) | `jobTitles.modals.view.title` (camelCase) ❌ |

The PHP translation file uses `job_titles` (underscore). CamelCase keys like `jobTitles.empty.title` will return the key itself instead of the translation, producing a broken UI.

**Recommendation**: Audit all frontend `translate()` calls and standardize on `job_titles.*` (matching the PHP file name).

---

### 4.2 Arabic Placeholders in English Translation File
**Severity**: 🟡 Medium  
**File**: [en/job_titles.php](file:///d:/Projects/Portfolio/Drexsta-old/lang/en/job_titles.php#L59-L60)

```php
'placeholder' => [
    'title' => 'ادخل المسمى الوظيفي',        // Arabic!
    'description' => 'ادخل وصف المسمى الوظيفي'  // Arabic!
],
```

The English translation file contains Arabic placeholder text. Users with English locale will see Arabic form placeholders.

---

### 4.3 Missing `stats` Key in Arabic Translation
**Severity**: 🟢 Low  
**File**: [ar/job_titles.php](file:///d:/Projects/Portfolio/Drexsta-old/lang/ar/job_titles.php)

The English file has a `stats` key block (lines 14–19) that is entirely missing from the Arabic file. This will cause fallback or missing translation issues.

---

### 4.4 EditJobTitleModal Uses Wrong HTTP Method
**Severity**: 🔴 High  
**File**: [EditJobTitleModal.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/EditJobTitleModal.tsx#L23)

```tsx
method="post"  // Should be "put" or "patch"
```

The edit modal calls the update route with `method="post"` instead of `"put"`. Laravel's `apiResource` routes expect `PUT/PATCH` for updates. This likely fails silently or hits the wrong route.

**Recommendation**: Change to `method="put"`.

---

### 4.5 Edit Route Missing Job Title ID
**Severity**: 🔴 High  
**File**: [EditJobTitleModal.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/EditJobTitleModal.tsx#L22)

```tsx
action={route('dashboard.job-titles.update')}
```

The update route requires the job title ID parameter (`route('dashboard.job-titles.update', jobTitle.id)`), but it's not being passed. This will generate an incorrect URL.

---

### 4.6 Hardcoded Cancel Link
**Severity**: 🟢 Low  
**File**: [JobTitleForm.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Components/JobTitles/JobTitleForm.tsx#L55)

```tsx
<Link href="/dashboard/job-titles" ...>
```

This hardcodes the URL instead of using `route('dashboard.job-titles.index')`. If the route prefix changes, this link breaks.

---

### 4.7 Console.log Left in Production Code
**Severity**: 🟡 Medium  
**File**: [AssignJobTitles.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Pages/Dashboard/Employees/AssignJobTitles.tsx#L24)

```tsx
console.log(employee);
```

Debug logging should not be in production code.

---

### 4.8 Non-Internationalized Strings in AssignJobTitles
**Severity**: 🟡 Medium  
**File**: [AssignJobTitles.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Pages/Dashboard/Employees/AssignJobTitles.tsx)

Multiple hardcoded English strings bypass the translation system:
- `"Assign Job Titles"` (line 68)
- `"Employee"` (line 81)
- `"Cancel"` (line 171)
- `"Current Job Titles"` (line 97)
- `"No Job Titles available"` (line 158)

---

### 4.9 Variable Naming: `department` Used for Job Titles
**Severity**: 🟡 Medium  
**File**: [AssignJobTitles.tsx](file:///d:/Projects/Portfolio/Drexsta-old/resources/js/Pages/Dashboard/Employees/AssignJobTitles.tsx#L100)

```tsx
{employee.jobTitles.map((department) => (
    <Badge key={department.id}>{department.title}</Badge>
))}
```

The iterator variable is named `department` when it's actually a `JobTitle`. This was likely copy-pasted from the departments assignment page.

---

### 4.10 Copy-Paste Comments in EmployeeActionsController
**Severity**: 🟢 Low  
**File**: [EmployeeActionsController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/Dashboard/Employee/EmployeeActionsController.php#L98)

```php
// Get all abilities for the current company  ← Wrong! This is job titles
$jobTitles = $company->jobTitles()...
```

Multiple methods have the comment "Get all abilities" when they're actually fetching departments or job titles. This indicates copy-paste without updating comments.

---

### 4.11 Soft Delete Without Cascade Check
**Severity**: 🟡 Medium  
**File**: [JobTitleController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/Dashboard/JobTitleController.php#L75)

```php
$jobTitle->delete();
```

The controller soft-deletes a job title without checking if employees are currently assigned to it. Orphaned pivot records in `job_title_user` will reference a soft-deleted job title. The system should either:
1. Prevent deletion if employees are assigned
2. Detach employees first
3. At minimum inform the user

---

### 4.12 ToggleIsActiveController Lacks Authorization
**Severity**: 🔴 High  
**File**: [ToggleIsActiveController.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Http/Controllers/ToggleIsActiveController.php)

The toggle controller does **no** policy/permission checks. Any authenticated user with access to the dashboard can toggle the status of any job title (or department, employment type, etc.) regardless of their permissions.

```php
// No $this->authorize() call anywhere
$model->update(['is_active' => !$model->is_active]);
```

---

### 4.13 `HasActiveScope` Contains Dead Code Logic
**Severity**: 🟢 Low  
**File**: [HasActiveScope.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Traits/GlobalScopes/HasActiveScope.php#L11-L12)

```php
$isActive = boolval($isActive);
if ($isActive === null) return $query; // This can NEVER be true after boolval()
```

After `boolval()`, `$isActive` is always `true` or `false`, never `null`. The null check is dead code.

---

### 4.14 SQL Injection Risk in HasSearchScope
**Severity**: 🟡 Medium  
**File**: [HasSearchScope.php](file:///d:/Projects/Portfolio/Drexsta-old/app/Traits/GlobalScopes/HasSearchScope.php#L15)

```php
return $query->whereAny($columns, 'LIKE', "%{$value}%");
```

While Laravel's query builder parameterizes the `$value`, the `$columns` array is not validated. If user-controlled data ever reaches the `$columns` parameter (which currently it doesn't, but the trait is generic), it could enable SQL injection. The trait should validate that columns exist on the model's table.

---

## 5. Summary & Priority Matrix

| Priority | Finding | Impact |
|---|---|---|
| 🔴 P0 | CompanyScope commented out (3.3) | Security — data leak across tenants |
| 🔴 P0 | ToggleIsActive lacks authorization (4.12) | Security — privilege escalation |
| 🔴 P1 | Edit modal wrong method + missing ID (4.4, 4.5) | Functional — update is broken |
| 🔴 P1 | No database indexes for search (3.1) | Performance — full table scans |
| 🔴 P1 | No JobTitleFactory (2.4) | Testability — cannot write tests |
| 🔴 P1 | Duplicate pivot models (L1) | Data integrity confusion |
| 🟡 P2 | No service layer (2.1) | Maintainability — SRP violation |
| 🟡 P2 | Translation key inconsistency (4.1) | UX — broken translations |
| 🟡 P2 | Arabic text in English file (4.2) | UX — wrong language shown |
| 🟡 P2 | Slug race condition (3.6) | Data integrity under load |
| 🟡 P2 | N+1 count query (3.2) | Performance |
| 🟡 P2 | Soft delete without cascade check (4.11) | Data integrity |
| 🟡 P2 | Hardcoded strings in AssignJobTitles (4.8) | i18n compliance |
| 🟢 P3 | Hardcoded pagination (O1) | Flexibility |
| 🟢 P3 | Copy-paste comments (4.10) | Code quality |
| 🟢 P3 | Dead code in HasActiveScope (4.13) | Code quality |
| 🟢 P3 | Console.log in production (4.7) | Professionalism |
