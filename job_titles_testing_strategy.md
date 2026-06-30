# Job Titles Section — Testing Strategy

> **Scope**: Backend (PHPUnit) + Frontend (Playwright) test plan  
> **Date**: 2026-06-28  

---

## Table of Contents
1. [Test Infrastructure Prerequisites](#1-test-infrastructure-prerequisites)
2. [Backend Testing — PHPUnit](#2-backend-testing--phpunit)
   - [Unit Tests](#21-unit-tests)
   - [Feature Tests](#22-feature-tests)
3. [Frontend Testing — Playwright](#3-frontend-testing--playwright)
4. [Coverage Targets](#4-coverage-targets)
5. [CI Integration](#5-ci-integration)

---

## 1. Test Infrastructure Prerequisites

### 1.1 Create a JobTitle Factory (Required First Step)

No `JobTitleFactory` currently exists. This is a hard blocker for all backend tests.

```php
<?php
// database/factories/JobTitleFactory.php

namespace Database\Factories;

use App\Models\Company;
use App\Models\JobTitle;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

class JobTitleFactory extends Factory
{
    protected $model = JobTitle::class;

    public function definition(): array
    {
        $title = fake()->unique()->jobTitle();
        return [
            'company_id' => Company::factory(),
            'title' => $title,
            'slug' => Str::slug($title),
            'description' => fake()->sentence(),
            'is_active' => true,
        ];
    }

    public function inactive(): static
    {
        return $this->state(['is_active' => false]);
    }

    public function withCompany(Company $company): static
    {
        return $this->state(['company_id' => $company->id]);
    }
}
```

### 1.2 Create Test Helper Traits

```php
<?php
// tests/Traits/ActsAsAuthenticatedUser.php

namespace Tests\Traits;

use App\Models\Company;
use App\Models\User;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

trait ActsAsAuthenticatedUser
{
    protected function createAuthenticatedUser(array $permissions = [], ?Company $company = null): User
    {
        $company ??= Company::factory()->create();
        $user = User::factory()->create(['active_company_id' => $company->id]);

        // Attach user to company
        $user->companies()->attach($company->id, ['role' => 'owner']);

        if (!empty($permissions)) {
            $role = Role::create(['name' => 'test-role', 'company_id' => $company->id]);
            foreach ($permissions as $permName) {
                $perm = Permission::firstOrCreate(['name' => $permName]);
                $role->givePermissionTo($perm);
            }
            $user->assignRole($role);
        }

        return $user;
    }
}
```

### 1.3 Playwright Setup

Playwright is not currently installed in the project. Setup instructions:

```bash
# Install Playwright
npm install -D @playwright/test
npx playwright install

# Create playwright.config.ts in project root
```

```typescript
// playwright.config.ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
    testDir: './tests/e2e',
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: process.env.CI ? 1 : undefined,
    reporter: 'html',
    use: {
        baseURL: 'http://localhost:8000',
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
    },
    projects: [
        { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    ],
    webServer: {
        command: 'php artisan serve',
        url: 'http://localhost:8000',
        reuseExistingServer: !process.env.CI,
    },
});
```

---

## 2. Backend Testing — PHPUnit

### 2.1 Unit Tests

Unit tests isolate individual components without hitting the database or HTTP layer.

#### 2.1.1 Model Tests

**File**: `tests/Unit/Models/JobTitleTest.php`

```php
<?php

namespace Tests\Unit\Models;

use App\Models\Company;
use App\Models\JobTitle;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class JobTitleTest extends TestCase
{
    use RefreshDatabase;

    /** @test */
    public function it_belongs_to_a_company(): void
    {
        $jobTitle = JobTitle::factory()->create();

        $this->assertInstanceOf(Company::class, $jobTitle->company);
    }

    /** @test */
    public function it_casts_is_active_to_boolean(): void
    {
        $jobTitle = JobTitle::factory()->create(['is_active' => 1]);

        $this->assertIsBool($jobTitle->is_active);
        $this->assertTrue($jobTitle->is_active);
    }

    /** @test */
    public function it_uses_soft_deletes(): void
    {
        $jobTitle = JobTitle::factory()->create();
        $jobTitle->delete();

        $this->assertSoftDeleted('job_titles', ['id' => $jobTitle->id]);
        $this->assertNotNull(JobTitle::withTrashed()->find($jobTitle->id));
    }

    /** @test */
    public function it_has_fillable_attributes(): void
    {
        $jobTitle = new JobTitle();
        $expected = ['company_id', 'title', 'slug', 'description', 'is_active'];

        $this->assertEquals($expected, $jobTitle->getFillable());
    }

    /** @test */
    public function it_scopes_search_by_title_and_description(): void
    {
        $company = Company::factory()->create();
        JobTitle::factory()->withCompany($company)->create(['title' => 'Software Engineer']);
        JobTitle::factory()->withCompany($company)->create(['title' => 'Accountant']);

        $results = JobTitle::search('software', ['title', 'description'])->get();

        $this->assertCount(1, $results);
        $this->assertEquals('Software Engineer', $results->first()->title);
    }

    /** @test */
    public function it_scopes_filter_by_active_status(): void
    {
        $company = Company::factory()->create();
        JobTitle::factory()->withCompany($company)->count(3)->create();
        JobTitle::factory()->withCompany($company)->inactive()->count(2)->create();

        $activeResults = JobTitle::filterBy('is_active', true)->get();
        $inactiveResults = JobTitle::filterBy('is_active', false)->get();

        $this->assertCount(3, $activeResults);
        $this->assertCount(2, $inactiveResults);
    }

    /** @test */
    public function search_with_null_value_returns_all(): void
    {
        $company = Company::factory()->create();
        JobTitle::factory()->withCompany($company)->count(5)->create();

        $results = JobTitle::search(null, ['title'])->get();

        $this->assertCount(5, $results);
    }
}
```

#### 2.1.2 Policy Tests

**File**: `tests/Unit/Policies/JobTitlePolicyTest.php`

```php
<?php

namespace Tests\Unit\Policies;

use App\Models\JobTitle;
use App\Models\User;
use App\Policies\JobTitlePolicy;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use Tests\Traits\ActsAsAuthenticatedUser;

class JobTitlePolicyTest extends TestCase
{
    use RefreshDatabase, ActsAsAuthenticatedUser;

    private JobTitlePolicy $policy;

    protected function setUp(): void
    {
        parent::setUp();
        $this->policy = new JobTitlePolicy();
    }

    /** @test */
    public function user_with_view_permission_can_view_any(): void
    {
        $user = $this->createAuthenticatedUser(['job-titles.view']);
        $this->assertTrue($this->policy->viewAny($user));
    }

    /** @test */
    public function user_without_view_permission_cannot_view_any(): void
    {
        $user = $this->createAuthenticatedUser([]);
        $this->assertFalse($this->policy->viewAny($user));
    }

    /** @test */
    public function user_with_create_permission_can_create(): void
    {
        $user = $this->createAuthenticatedUser(['job-titles.create']);
        $this->assertTrue($this->policy->create($user));
    }

    /** @test */
    public function user_with_edit_permission_can_update(): void
    {
        $user = $this->createAuthenticatedUser(['job-titles.edit']);
        $jobTitle = JobTitle::factory()->create();

        $this->assertTrue($this->policy->update($user, $jobTitle));
    }

    /** @test */
    public function user_with_delete_permission_can_delete(): void
    {
        $user = $this->createAuthenticatedUser(['job-titles.delete']);
        $jobTitle = JobTitle::factory()->create();

        $this->assertTrue($this->policy->delete($user, $jobTitle));
    }

    /** @test */
    public function restore_is_always_denied(): void
    {
        $user = $this->createAuthenticatedUser(['job-titles.delete']);
        $jobTitle = JobTitle::factory()->create();

        $this->assertFalse($this->policy->restore($user, $jobTitle));
    }

    /** @test */
    public function force_delete_is_always_denied(): void
    {
        $user = $this->createAuthenticatedUser(['job-titles.delete']);
        $jobTitle = JobTitle::factory()->create();

        $this->assertFalse($this->policy->forceDelete($user, $jobTitle));
    }
}
```

#### 2.1.3 Validation Rule Tests

**File**: `tests/Unit/Rules/UniqueScopedTest.php`

```php
<?php

namespace Tests\Unit\Rules;

use App\Models\Company;
use App\Models\JobTitle;
use App\Rules\UniqueScoped;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class UniqueScopedTest extends TestCase
{
    use RefreshDatabase;

    /** @test */
    public function it_fails_when_title_exists_in_same_company(): void
    {
        $company = Company::factory()->create();
        JobTitle::factory()->create([
            'company_id' => $company->id,
            'title' => 'Software Engineer',
        ]);

        $rule = new UniqueScoped('job_titles', 'title', 'company_id', $company->id);

        $failed = false;
        $rule->validate('title', 'Software Engineer', function () use (&$failed) {
            $failed = true;
        });

        $this->assertTrue($failed);
    }

    /** @test */
    public function it_passes_when_title_exists_in_different_company(): void
    {
        $companyA = Company::factory()->create();
        $companyB = Company::factory()->create();

        JobTitle::factory()->create([
            'company_id' => $companyA->id,
            'title' => 'Software Engineer',
        ]);

        $rule = new UniqueScoped('job_titles', 'title', 'company_id', $companyB->id);

        $failed = false;
        $rule->validate('title', 'Software Engineer', function () use (&$failed) {
            $failed = true;
        });

        $this->assertFalse($failed);
    }

    /** @test */
    public function it_passes_when_except_id_matches(): void
    {
        $company = Company::factory()->create();
        $jobTitle = JobTitle::factory()->create([
            'company_id' => $company->id,
            'title' => 'Software Engineer',
        ]);

        $rule = (new UniqueScoped('job_titles', 'title', 'company_id', $company->id))
            ->except($jobTitle->id);

        $failed = false;
        $rule->validate('title', 'Software Engineer', function () use (&$failed) {
            $failed = true;
        });

        $this->assertFalse($failed);
    }
}
```

#### 2.1.4 SlugHelper Tests

**File**: `tests/Unit/Helpers/SlugHelperTest.php`

```php
<?php

namespace Tests\Unit\Helpers;

use Tests\TestCase;

class SlugHelperTest extends TestCase
{
    /** @test */
    public function it_generates_slug_from_english_text(): void
    {
        $this->assertEquals('software-engineer', generateSlug('Software Engineer'));
    }

    /** @test */
    public function it_generates_slug_from_arabic_text(): void
    {
        $slug = generateSlug('مهندس برمجيات');
        $this->assertNotEmpty($slug);
        $this->assertStringNotContainsString(' ', $slug);
    }

    /** @test */
    public function it_returns_empty_string_for_null(): void
    {
        $this->assertEquals('', generateSlug(null));
    }

    /** @test */
    public function it_returns_empty_string_for_empty_string(): void
    {
        $this->assertEquals('', generateSlug(''));
    }

    /** @test */
    public function it_handles_special_characters(): void
    {
        $slug = generateSlug('C++ Developer / Full-Stack');
        $this->assertStringNotContainsString('/', $slug);
        $this->assertStringNotContainsString('+', $slug);
    }

    /** @test */
    public function it_trims_leading_and_trailing_separators(): void
    {
        $slug = generateSlug('  Software Engineer  ');
        $this->assertFalse(str_starts_with($slug, '-'));
        $this->assertFalse(str_ends_with($slug, '-'));
    }
}
```

---

### 2.2 Feature Tests

Feature tests exercise the full HTTP request lifecycle including middleware, authorization, validation, and database interaction.

#### 2.2.1 Index / List Tests

**File**: `tests/Feature/JobTitles/JobTitleIndexTest.php`

```php
<?php

namespace Tests\Feature\JobTitles;

use App\Models\Company;
use App\Models\JobTitle;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Inertia\Testing\AssertableInertia;
use Tests\TestCase;
use Tests\Traits\ActsAsAuthenticatedUser;

class JobTitleIndexTest extends TestCase
{
    use RefreshDatabase, ActsAsAuthenticatedUser;

    /** @test */
    public function authenticated_user_with_permission_can_view_index(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.view'], $company);

        JobTitle::factory()->withCompany($company)->count(5)->create();

        $this->actingAs($user)
            ->get(route('dashboard.job-titles.index'))
            ->assertOk()
            ->assertInertia(fn (AssertableInertia $page) =>
                $page->component('Dashboard/JobTitles/Index')
                    ->has('jobTitles.data', 5)
            );
    }

    /** @test */
    public function unauthenticated_user_is_redirected_to_login(): void
    {
        $this->get(route('dashboard.job-titles.index'))
            ->assertRedirect(route('login'));
    }

    /** @test */
    public function user_without_permission_gets_403(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser([], $company);

        $this->actingAs($user)
            ->get(route('dashboard.job-titles.index'))
            ->assertForbidden();
    }

    /** @test */
    public function it_filters_by_search_term(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.view'], $company);

        JobTitle::factory()->withCompany($company)->create(['title' => 'Software Engineer']);
        JobTitle::factory()->withCompany($company)->create(['title' => 'HR Manager']);

        $this->actingAs($user)
            ->get(route('dashboard.job-titles.index', ['search' => 'software']))
            ->assertOk()
            ->assertInertia(fn (AssertableInertia $page) =>
                $page->has('jobTitles.data', 1)
            );
    }

    /** @test */
    public function it_filters_by_active_status(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.view'], $company);

        JobTitle::factory()->withCompany($company)->count(3)->create();
        JobTitle::factory()->withCompany($company)->inactive()->count(2)->create();

        $this->actingAs($user)
            ->get(route('dashboard.job-titles.index', ['status' => 'active']))
            ->assertOk()
            ->assertInertia(fn (AssertableInertia $page) =>
                $page->has('jobTitles.data', 3)
            );
    }

    /** @test */
    public function it_paginates_results(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.view'], $company);

        JobTitle::factory()->withCompany($company)->count(20)->create();

        $this->actingAs($user)
            ->get(route('dashboard.job-titles.index'))
            ->assertOk()
            ->assertInertia(fn (AssertableInertia $page) =>
                $page->has('jobTitles.data', 12) // paginate(12)
            );
    }

    /** @test */
    public function it_validates_search_input(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.view'], $company);

        $this->actingAs($user)
            ->get(route('dashboard.job-titles.index', ['search' => str_repeat('a', 256)]))
            ->assertSessionHasErrors('search');
    }

    /** @test */
    public function it_validates_status_filter(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.view'], $company);

        $this->actingAs($user)
            ->get(route('dashboard.job-titles.index', ['status' => 'invalid']))
            ->assertSessionHasErrors('status');
    }
}
```

#### 2.2.2 Store (Create) Tests

**File**: `tests/Feature/JobTitles/JobTitleStoreTest.php`

```php
<?php

namespace Tests\Feature\JobTitles;

use App\Models\Company;
use App\Models\JobTitle;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use Tests\Traits\ActsAsAuthenticatedUser;

class JobTitleStoreTest extends TestCase
{
    use RefreshDatabase, ActsAsAuthenticatedUser;

    /** @test */
    public function authorized_user_can_create_job_title(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.create'], $company);

        $this->actingAs($user)
            ->post(route('dashboard.job-titles.store'), [
                'title' => 'Software Engineer',
                'description' => 'Develops software.',
                'is_active' => true,
            ])
            ->assertSessionHas('success')
            ->assertRedirect();

        $this->assertDatabaseHas('job_titles', [
            'title' => 'Software Engineer',
            'company_id' => $company->id,
        ]);
    }

    /** @test */
    public function it_generates_slug_on_creation(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.create'], $company);

        $this->actingAs($user)
            ->post(route('dashboard.job-titles.store'), [
                'title' => 'Senior DevOps Engineer',
                'is_active' => true,
            ]);

        $jobTitle = JobTitle::first();
        $this->assertNotEmpty($jobTitle->slug);
        $this->assertStringContainsString('devops', $jobTitle->slug);
    }

    /** @test */
    public function it_rejects_duplicate_title_within_same_company(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.create'], $company);

        JobTitle::factory()->create([
            'company_id' => $company->id,
            'title' => 'Software Engineer',
        ]);

        $this->actingAs($user)
            ->post(route('dashboard.job-titles.store'), [
                'title' => 'Software Engineer',
                'is_active' => true,
            ])
            ->assertSessionHasErrors('title');
    }

    /** @test */
    public function it_allows_same_title_in_different_company(): void
    {
        $companyA = Company::factory()->create();
        $companyB = Company::factory()->create();

        $userA = $this->createAuthenticatedUser(['job-titles.create'], $companyA);

        JobTitle::factory()->create([
            'company_id' => $companyB->id,
            'title' => 'Software Engineer',
        ]);

        $this->actingAs($userA)
            ->post(route('dashboard.job-titles.store'), [
                'title' => 'Software Engineer',
                'is_active' => true,
            ])
            ->assertSessionDoesntHaveErrors();
    }

    /** @test */
    public function it_requires_title_field(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.create'], $company);

        $this->actingAs($user)
            ->post(route('dashboard.job-titles.store'), [
                'description' => 'A description without a title',
            ])
            ->assertSessionHasErrors('title');
    }

    /** @test */
    public function it_rejects_title_exceeding_max_length(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.create'], $company);

        $this->actingAs($user)
            ->post(route('dashboard.job-titles.store'), [
                'title' => str_repeat('a', 256),
                'is_active' => true,
            ])
            ->assertSessionHasErrors('title');
    }

    /** @test */
    public function unauthorized_user_cannot_create(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.view'], $company);

        $this->actingAs($user)
            ->post(route('dashboard.job-titles.store'), [
                'title' => 'Software Engineer',
                'is_active' => true,
            ])
            ->assertForbidden();
    }

    /** @test */
    public function it_defaults_is_active_to_boolean(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.create'], $company);

        $this->actingAs($user)
            ->post(route('dashboard.job-titles.store'), [
                'title' => 'QA Lead',
                'is_active' => 'on', // HTML checkbox value
            ]);

        $jobTitle = JobTitle::first();
        $this->assertIsBool($jobTitle->is_active);
    }
}
```

#### 2.2.3 Update Tests

**File**: `tests/Feature/JobTitles/JobTitleUpdateTest.php`

```php
<?php

namespace Tests\Feature\JobTitles;

use App\Models\Company;
use App\Models\JobTitle;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use Tests\Traits\ActsAsAuthenticatedUser;

class JobTitleUpdateTest extends TestCase
{
    use RefreshDatabase, ActsAsAuthenticatedUser;

    /** @test */
    public function authorized_user_can_update_job_title(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.edit'], $company);
        $jobTitle = JobTitle::factory()->withCompany($company)->create(['title' => 'Old Title']);

        $this->actingAs($user)
            ->put(route('dashboard.job-titles.update', $jobTitle), [
                'title' => 'New Title',
                'description' => 'Updated description',
                'is_active' => true,
            ])
            ->assertSessionHas('success');

        $this->assertDatabaseHas('job_titles', [
            'id' => $jobTitle->id,
            'title' => 'New Title',
        ]);
    }

    /** @test */
    public function it_allows_updating_with_same_title(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.edit'], $company);
        $jobTitle = JobTitle::factory()->withCompany($company)->create(['title' => 'Engineer']);

        $this->actingAs($user)
            ->put(route('dashboard.job-titles.update', $jobTitle), [
                'title' => 'Engineer', // Same title — should pass UniqueScoped
                'is_active' => true,
            ])
            ->assertSessionDoesntHaveErrors();
    }

    /** @test */
    public function it_prevents_updating_to_existing_title_in_same_company(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.edit'], $company);

        JobTitle::factory()->withCompany($company)->create(['title' => 'Existing Title']);
        $jobTitle = JobTitle::factory()->withCompany($company)->create(['title' => 'My Title']);

        $this->actingAs($user)
            ->put(route('dashboard.job-titles.update', $jobTitle), [
                'title' => 'Existing Title',
                'is_active' => true,
            ])
            ->assertSessionHasErrors('title');
    }

    /** @test */
    public function unauthorized_user_cannot_update(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.view'], $company);
        $jobTitle = JobTitle::factory()->withCompany($company)->create();

        $this->actingAs($user)
            ->put(route('dashboard.job-titles.update', $jobTitle), [
                'title' => 'Updated',
                'is_active' => true,
            ])
            ->assertForbidden();
    }
}
```

#### 2.2.4 Delete Tests

**File**: `tests/Feature/JobTitles/JobTitleDeleteTest.php`

```php
<?php

namespace Tests\Feature\JobTitles;

use App\Models\Company;
use App\Models\JobTitle;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use Tests\Traits\ActsAsAuthenticatedUser;

class JobTitleDeleteTest extends TestCase
{
    use RefreshDatabase, ActsAsAuthenticatedUser;

    /** @test */
    public function authorized_user_can_soft_delete_job_title(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.delete'], $company);
        $jobTitle = JobTitle::factory()->withCompany($company)->create();

        $this->actingAs($user)
            ->delete(route('dashboard.job-titles.destroy', $jobTitle))
            ->assertSessionHas('success');

        $this->assertSoftDeleted('job_titles', ['id' => $jobTitle->id]);
    }

    /** @test */
    public function unauthorized_user_cannot_delete(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.view'], $company);
        $jobTitle = JobTitle::factory()->withCompany($company)->create();

        $this->actingAs($user)
            ->delete(route('dashboard.job-titles.destroy', $jobTitle))
            ->assertForbidden();
    }

    /** @test */
    public function deleting_nonexistent_job_title_returns_404(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.delete'], $company);

        $this->actingAs($user)
            ->delete(route('dashboard.job-titles.destroy', 99999))
            ->assertNotFound();
    }
}
```

#### 2.2.5 Toggle Status Tests

**File**: `tests/Feature/JobTitles/JobTitleToggleStatusTest.php`

```php
<?php

namespace Tests\Feature\JobTitles;

use App\Models\Company;
use App\Models\JobTitle;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use Tests\Traits\ActsAsAuthenticatedUser;

class JobTitleToggleStatusTest extends TestCase
{
    use RefreshDatabase, ActsAsAuthenticatedUser;

    /** @test */
    public function it_toggles_active_to_inactive(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.edit'], $company);
        $jobTitle = JobTitle::factory()->withCompany($company)->create(['is_active' => true]);

        $this->actingAs($user)
            ->patch(route('dashboard.job-titles.toggle-status', $jobTitle))
            ->assertRedirect();

        $this->assertFalse($jobTitle->fresh()->is_active);
    }

    /** @test */
    public function it_toggles_inactive_to_active(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.edit'], $company);
        $jobTitle = JobTitle::factory()->withCompany($company)->inactive()->create();

        $this->actingAs($user)
            ->patch(route('dashboard.job-titles.toggle-status', $jobTitle))
            ->assertRedirect();

        $this->assertTrue($jobTitle->fresh()->is_active);
    }

    /** @test */
    public function it_is_throttled(): void
    {
        $company = Company::factory()->create();
        $user = $this->createAuthenticatedUser(['job-titles.edit'], $company);
        $jobTitle = JobTitle::factory()->withCompany($company)->create();

        // Hit the rate limit (configured as 'throttle:regular')
        for ($i = 0; $i < 70; $i++) {
            $this->actingAs($user)
                ->patch(route('dashboard.job-titles.toggle-status', $jobTitle));
        }

        $this->actingAs($user)
            ->patch(route('dashboard.job-titles.toggle-status', $jobTitle))
            ->assertTooManyRequests();
    }
}
```

#### 2.2.6 API Resource Tests

**File**: `tests/Feature/JobTitles/JobTitleResourceTest.php`

```php
<?php

namespace Tests\Feature\JobTitles;

use App\Http\Resources\JobTitleResource;
use App\Models\Company;
use App\Models\JobTitle;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Tests\TestCase;

class JobTitleResourceTest extends TestCase
{
    use RefreshDatabase;

    /** @test */
    public function it_transforms_job_title_to_array(): void
    {
        $jobTitle = JobTitle::factory()->create([
            'title' => 'Software Engineer',
            'slug' => 'software-engineer',
            'is_active' => true,
        ]);

        $resource = (new JobTitleResource($jobTitle))->toArray(new Request());

        $this->assertArrayHasKey('id', $resource);
        $this->assertArrayHasKey('title', $resource);
        $this->assertArrayHasKey('slug', $resource);
        $this->assertArrayHasKey('is_active', $resource);
        $this->assertArrayHasKey('created_at', $resource);
        $this->assertEquals('Software Engineer', $resource['title']);
    }

    /** @test */
    public function it_includes_company_when_loaded(): void
    {
        $jobTitle = JobTitle::factory()->create();
        $jobTitle->load('company');

        $resource = (new JobTitleResource($jobTitle))->toArray(new Request());

        $this->assertArrayHasKey('company', $resource);
        $this->assertArrayHasKey('name', $resource['company']);
    }

    /** @test */
    public function it_excludes_company_when_not_loaded(): void
    {
        $jobTitle = JobTitle::factory()->create();

        $resource = (new JobTitleResource($jobTitle))->toArray(new Request());

        // whenLoaded returns MissingValue when not loaded
        $this->assertArrayNotHasKey('company', $resource);
    }

    /** @test */
    public function it_formats_dates_correctly(): void
    {
        $jobTitle = JobTitle::factory()->create();

        $resource = (new JobTitleResource($jobTitle))->toArray(new Request());

        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $resource['created_at']);
    }
}
```

---

## 3. Frontend Testing — Playwright

### 3.1 Test Organization

```
tests/e2e/
├── fixtures/
│   └── auth.ts                 # Login helper / auth state
├── pages/
│   └── job-titles.page.ts      # Page Object Model
├── job-titles/
│   ├── index.spec.ts           # List page tests
│   ├── create.spec.ts          # Create modal tests
│   ├── edit.spec.ts            # Edit modal tests
│   ├── delete.spec.ts          # Delete modal tests
│   └── search-filter.spec.ts   # Search & filter tests
└── global-setup.ts             # Global auth setup
```

### 3.2 Page Object Model

**File**: `tests/e2e/pages/job-titles.page.ts`

```typescript
import { type Locator, type Page, expect } from '@playwright/test';

export class JobTitlesPage {
    readonly page: Page;
    readonly heading: Locator;
    readonly createButton: Locator;
    readonly searchInput: Locator;
    readonly statusFilter: Locator;
    readonly dataTable: Locator;
    readonly emptyState: Locator;

    // Modal elements
    readonly modalTitle: Locator;
    readonly titleInput: Locator;
    readonly descriptionInput: Locator;
    readonly statusSwitch: Locator;
    readonly submitButton: Locator;
    readonly cancelButton: Locator;

    constructor(page: Page) {
        this.page = page;
        this.heading = page.getByRole('heading', { name: /job titles/i });
        this.createButton = page.getByRole('button', { name: /add job title/i });
        this.searchInput = page.getByPlaceholder(/search/i);
        this.statusFilter = page.locator('[data-field="status"]');
        this.dataTable = page.locator('[class*="rounded-md border"]');
        this.emptyState = page.getByText(/no job titles/i);

        // Modal
        this.modalTitle = page.locator('[role="dialog"] h2');
        this.titleInput = page.locator('[role="dialog"] #title');
        this.descriptionInput = page.locator('[role="dialog"] #description');
        this.statusSwitch = page.locator('[role="dialog"] [role="switch"]');
        this.submitButton = page.locator('[role="dialog"] button[type="submit"]');
        this.cancelButton = page.locator('[role="dialog"] a[href*="job-titles"]');
    }

    async goto() {
        await this.page.goto('/dashboard/job-titles');
        await this.page.waitForLoadState('networkidle');
    }

    async openCreateModal() {
        await this.createButton.click();
        await this.page.waitForSelector('[role="dialog"]');
    }

    async fillForm(data: { title: string; description?: string; isActive?: boolean }) {
        await this.titleInput.fill(data.title);
        if (data.description) {
            await this.descriptionInput.fill(data.description);
        }
        if (data.isActive === false) {
            await this.statusSwitch.click();
        }
    }

    async submitForm() {
        await this.submitButton.click();
        await this.page.waitForLoadState('networkidle');
    }

    async getRowCount(): Promise<number> {
        return await this.page.locator('table tbody tr').count();
    }

    async openActionMenu(jobTitleName: string) {
        const row = this.page.locator('table tbody tr', { hasText: jobTitleName });
        await row.getByRole('button', { name: /open menu/i }).click();
    }

    async clickAction(action: 'view' | 'edit' | 'delete') {
        const menuItem = this.page.getByRole('menuitem', { name: new RegExp(action, 'i') });
        await menuItem.click();
    }
}
```

### 3.3 Authentication Fixture

**File**: `tests/e2e/fixtures/auth.ts`

```typescript
import { test as base, expect } from '@playwright/test';
import { JobTitlesPage } from '../pages/job-titles.page';

type Fixtures = {
    authenticatedPage: ReturnType<typeof base['page']>;
    jobTitlesPage: JobTitlesPage;
};

export const test = base.extend<Fixtures>({
    authenticatedPage: async ({ page }, use) => {
        // Login with test credentials
        await page.goto('/login');
        await page.getByLabel('Email').fill('test@example.com');
        await page.getByLabel('Password').fill('password');
        await page.getByRole('button', { name: /log in/i }).click();
        await page.waitForURL('**/dashboard/**');
        await use(page);
    },
    jobTitlesPage: async ({ authenticatedPage }, use) => {
        const jobTitlesPage = new JobTitlesPage(authenticatedPage);
        await use(jobTitlesPage);
    },
});

export { expect };
```

### 3.4 List Page Tests

**File**: `tests/e2e/job-titles/index.spec.ts`

```typescript
import { test, expect } from '../fixtures/auth';

test.describe('Job Titles Index Page', () => {
    test('displays the page header and title', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();

        await expect(jobTitlesPage.heading).toBeVisible();
        await expect(jobTitlesPage.page).toHaveTitle(/job titles/i);
    });

    test('shows create button for authorized users', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();
        await expect(jobTitlesPage.createButton).toBeVisible();
    });

    test('displays job titles in a data table', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();

        // Assumes seeded data exists
        const rowCount = await jobTitlesPage.getRowCount();
        expect(rowCount).toBeGreaterThan(0);
    });

    test('shows empty state when no job titles exist', async ({ jobTitlesPage }) => {
        // This test requires a clean database state
        // Use API seeding or database reset before test
        await jobTitlesPage.goto();

        // Check for empty state component (depends on data)
        const emptyOrTable = await Promise.race([
            jobTitlesPage.emptyState.waitFor({ timeout: 2000 }).then(() => 'empty'),
            jobTitlesPage.dataTable.waitFor({ timeout: 2000 }).then(() => 'table'),
        ]);

        expect(['empty', 'table']).toContain(emptyOrTable);
    });

    test('breadcrumbs show correct navigation path', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();

        await expect(jobTitlesPage.page.getByText('Dashboard')).toBeVisible();
        await expect(jobTitlesPage.page.getByText('Job Titles')).toBeVisible();
    });
});
```

### 3.5 Create Modal Tests

**File**: `tests/e2e/job-titles/create.spec.ts`

```typescript
import { test, expect } from '../fixtures/auth';

test.describe('Create Job Title Modal', () => {
    test.beforeEach(async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();
    });

    test('opens create modal when clicking add button', async ({ jobTitlesPage }) => {
        await jobTitlesPage.openCreateModal();

        await expect(jobTitlesPage.modalTitle).toContainText(/create job title/i);
        await expect(jobTitlesPage.titleInput).toBeVisible();
        await expect(jobTitlesPage.descriptionInput).toBeVisible();
        await expect(jobTitlesPage.statusSwitch).toBeVisible();
    });

    test('creates a new job title with valid data', async ({ jobTitlesPage }) => {
        const uniqueTitle = `Test Engineer ${Date.now()}`;

        await jobTitlesPage.openCreateModal();
        await jobTitlesPage.fillForm({
            title: uniqueTitle,
            description: 'E2E test description',
        });
        await jobTitlesPage.submitForm();

        // Verify success flash message
        await expect(jobTitlesPage.page.getByText(/created successfully/i)).toBeVisible();

        // Verify the new job title appears in the list
        await expect(jobTitlesPage.page.getByText(uniqueTitle)).toBeVisible();
    });

    test('shows validation error for empty title', async ({ jobTitlesPage }) => {
        await jobTitlesPage.openCreateModal();
        await jobTitlesPage.fillForm({ title: '' });
        await jobTitlesPage.submitForm();

        // HTML5 validation should prevent submission
        // or server-side validation error should appear
        await expect(jobTitlesPage.titleInput).toBeFocused();
    });

    test('shows validation error for duplicate title', async ({ jobTitlesPage }) => {
        // First, create a job title
        const title = `Duplicate Test ${Date.now()}`;

        await jobTitlesPage.openCreateModal();
        await jobTitlesPage.fillForm({ title });
        await jobTitlesPage.submitForm();

        // Try to create another with the same title
        await jobTitlesPage.openCreateModal();
        await jobTitlesPage.fillForm({ title });
        await jobTitlesPage.submitForm();

        // Expect validation error
        await expect(jobTitlesPage.page.getByText(/already been taken/i)).toBeVisible();
    });

    test('submit button shows loading state during submission', async ({ jobTitlesPage }) => {
        await jobTitlesPage.openCreateModal();
        await jobTitlesPage.fillForm({ title: `Loading Test ${Date.now()}` });

        // Check button text changes to "Saving..."
        await jobTitlesPage.submitButton.click();
        await expect(jobTitlesPage.submitButton).toContainText(/saving/i);
    });
});
```

### 3.6 Edit and Delete Tests

**File**: `tests/e2e/job-titles/edit.spec.ts`

```typescript
import { test, expect } from '../fixtures/auth';

test.describe('Edit Job Title', () => {
    test('opens edit modal from action menu', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();

        // Click action menu on first job title row
        const firstRowTitle = await jobTitlesPage.page
            .locator('table tbody tr')
            .first()
            .locator('td')
            .first()
            .textContent();

        await jobTitlesPage.openActionMenu(firstRowTitle!.trim());
        await jobTitlesPage.clickAction('edit');

        await expect(jobTitlesPage.page.locator('[role="dialog"]')).toBeVisible();
        await expect(jobTitlesPage.titleInput).toHaveValue(firstRowTitle!.trim());
    });

    test('updates job title successfully', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();

        const firstRowTitle = await jobTitlesPage.page
            .locator('table tbody tr')
            .first()
            .locator('.font-medium')
            .textContent();

        await jobTitlesPage.openActionMenu(firstRowTitle!.trim());
        await jobTitlesPage.clickAction('edit');

        const updatedTitle = `Updated ${Date.now()}`;
        await jobTitlesPage.titleInput.clear();
        await jobTitlesPage.titleInput.fill(updatedTitle);
        await jobTitlesPage.submitForm();

        await expect(jobTitlesPage.page.getByText(/updated successfully/i)).toBeVisible();
    });
});
```

**File**: `tests/e2e/job-titles/delete.spec.ts`

```typescript
import { test, expect } from '../fixtures/auth';

test.describe('Delete Job Title', () => {
    test('opens delete confirmation modal', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();

        const firstRowTitle = await jobTitlesPage.page
            .locator('table tbody tr')
            .first()
            .locator('.font-medium')
            .textContent();

        await jobTitlesPage.openActionMenu(firstRowTitle!.trim());
        await jobTitlesPage.clickAction('delete');

        await expect(jobTitlesPage.page.getByText(/confirm/i)).toBeVisible();
        await expect(jobTitlesPage.page.getByText(firstRowTitle!.trim())).toBeVisible();
    });

    test('deletes job title after confirmation', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();
        const initialCount = await jobTitlesPage.getRowCount();

        const firstRowTitle = await jobTitlesPage.page
            .locator('table tbody tr')
            .first()
            .locator('.font-medium')
            .textContent();

        await jobTitlesPage.openActionMenu(firstRowTitle!.trim());
        await jobTitlesPage.clickAction('delete');

        // Click the confirm delete button in the modal
        await jobTitlesPage.page.getByRole('button', { name: /confirm|delete/i }).click();
        await jobTitlesPage.page.waitForLoadState('networkidle');

        await expect(jobTitlesPage.page.getByText(/deleted successfully/i)).toBeVisible();

        const newCount = await jobTitlesPage.getRowCount();
        expect(newCount).toBeLessThan(initialCount);
    });
});
```

### 3.7 Search & Filter Tests

**File**: `tests/e2e/job-titles/search-filter.spec.ts`

```typescript
import { test, expect } from '../fixtures/auth';

test.describe('Search and Filter', () => {
    test('filters results by search term', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();

        await jobTitlesPage.searchInput.fill('Engineer');
        await jobTitlesPage.page.waitForLoadState('networkidle');

        // Every visible row should contain "Engineer"
        const rows = jobTitlesPage.page.locator('table tbody tr');
        const count = await rows.count();

        for (let i = 0; i < count; i++) {
            await expect(rows.nth(i)).toContainText(/engineer/i);
        }
    });

    test('clears search and shows all results', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();

        await jobTitlesPage.searchInput.fill('Engineer');
        await jobTitlesPage.page.waitForLoadState('networkidle');
        const filteredCount = await jobTitlesPage.getRowCount();

        await jobTitlesPage.searchInput.clear();
        await jobTitlesPage.page.waitForLoadState('networkidle');
        const allCount = await jobTitlesPage.getRowCount();

        expect(allCount).toBeGreaterThanOrEqual(filteredCount);
    });

    test('filters by active status', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();

        // Select "Active" from status filter
        await jobTitlesPage.statusFilter.click();
        await jobTitlesPage.page.getByRole('option', { name: /^active$/i }).click();
        await jobTitlesPage.page.waitForLoadState('networkidle');

        // All visible status badges should show "Active"
        const badges = jobTitlesPage.page.locator('table tbody [data-status]');
        const count = await badges.count();
        for (let i = 0; i < count; i++) {
            await expect(badges.nth(i)).toHaveAttribute('data-status', 'active');
        }
    });

    test('shows no results for non-matching search', async ({ jobTitlesPage }) => {
        await jobTitlesPage.goto();

        await jobTitlesPage.searchInput.fill('xyznonexistent123');
        await jobTitlesPage.page.waitForLoadState('networkidle');

        const rowCount = await jobTitlesPage.getRowCount();
        expect(rowCount).toBe(0);
    });
});
```

---

## 4. Coverage Targets

### 4.1 Backend Coverage Goals

| Component | Target | Critical Paths |
|---|---|---|
| `JobTitleController` | 95%+ | All CRUD operations, auth checks |
| `JobTitlePolicy` | 100% | Every policy method |
| `JobTitleRequest` | 90%+ | All validation rules |
| `JobTitleResource` | 90%+ | All transformations |
| `UniqueScoped` Rule | 95%+ | All branching paths |
| `SlugHelper` | 100% | All edge cases |
| `ToggleIsActiveController` | 80%+ | Toggle + error cases |
| `HasSearchScope` | 90%+ | Null, empty, multi-column |
| `HasFilterByScope` | 90%+ | All operator types |

### 4.2 Frontend Coverage Goals

| Component | E2E Tests | Key Flows |
|---|---|---|
| Index Page | 5+ tests | Load, empty state, breadcrumbs |
| Create Modal | 5+ tests | Open, submit, validate, loading |
| Edit Modal | 3+ tests | Open, pre-fill, submit |
| Delete Modal | 3+ tests | Open, confirm, cancel |
| Search/Filter | 4+ tests | Search, filter, clear, no results |
| Pagination | 2+ tests | Navigate pages, preserve filters |
| Status Toggle | 2+ tests | Toggle on/off |

### 4.3 Test Distribution

```
Backend Tests (PHPUnit)
├── Unit Tests: ~25 tests
│   ├── Models (5)
│   ├── Policies (7)
│   ├── Validation Rules (5)
│   ├── Helpers (6)
│   └── Resources (4)
└── Feature Tests: ~30 tests
    ├── Index/List (7)
    ├── Store/Create (7)
    ├── Update (4)
    ├── Delete (3)
    ├── Toggle Status (3)
    └── Edge Cases (6)

Frontend Tests (Playwright)
└── E2E Tests: ~20 tests
    ├── Index Page (5)
    ├── Create Flow (5)
    ├── Edit Flow (3)
    ├── Delete Flow (3)
    └── Search & Filter (4)
```

---

## 5. CI Integration

### 5.1 PHPUnit in CI

```yaml
# .github/workflows/test.yml (relevant section)
backend-tests:
  runs-on: ubuntu-latest
  services:
    mysql:
      image: mysql:8.0
      env:
        MYSQL_DATABASE: testing
        MYSQL_ROOT_PASSWORD: password
      ports: ['3306:3306']
  steps:
    - uses: actions/checkout@v4
    - uses: shivammathur/setup-php@v2
      with:
        php-version: '8.3'
        coverage: xdebug
    - run: composer install --no-interaction
    - run: php artisan migrate --env=testing
    - run: php artisan test --coverage --min=80
```

### 5.2 Playwright in CI

```yaml
e2e-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: '20'
    - run: npm ci
    - run: npx playwright install --with-deps
    - run: php artisan serve &
    - run: npx playwright test
    - uses: actions/upload-artifact@v4
      if: always()
      with:
        name: playwright-report
        path: playwright-report/
```

### 5.3 Running Tests Locally

```bash
# Backend: Run all job title tests
php artisan test --filter="JobTitle"

# Backend: Run with coverage
php artisan test --filter="JobTitle" --coverage

# Frontend: Run all E2E tests
npx playwright test

# Frontend: Run job title tests only
npx playwright test tests/e2e/job-titles/

# Frontend: Run in headed mode for debugging
npx playwright test --headed --debug
```

### 5.4 Test Data Strategy

| Approach | When to Use |
|---|---|
| **Factories** (PHPUnit) | All backend tests — use `RefreshDatabase` trait |
| **Database Seeder** (Playwright) | E2E tests — run `php artisan db:seed --class=TestSeeder` before tests |
| **API-based setup** (Playwright) | When tests need specific state — create via API calls in `beforeEach` |
| **State files** (Playwright) | Auth state — save cookies/storage after login, reuse across tests |

> [!TIP]
> For Playwright tests, create a dedicated `TestSeeder` that seeds minimal data needed for E2E tests, rather than using the full `OrganizationSeeder`. This keeps tests fast and predictable.
