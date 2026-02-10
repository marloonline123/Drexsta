<?php

namespace App\Http\Controllers\Dashboard\Employee;

use App\Http\Controllers\Controller;
use App\Http\Resources\AbilityResource;
use App\Http\Resources\DepartmentResource;
use App\Http\Resources\EmployeeResource;
use App\Http\Resources\JobTitleResource;
use App\Http\Resources\RoleResource;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Services\Business\AbilityService;
use App\Models\User;
use Inertia\Inertia;

class EmployeeActionsController extends Controller
{
    public function __construct(protected AbilityService $abilityService)
    {
    }

    /**
     * Show the assign roles form.
     */
    public function showAssignRoles(User $employee)
    {
        // $this->authorize('update', $employee);

        $user = Auth::user();
        $company = $user->activeCompany;

        $employee->load('roles', 'permissions');

        // Get all roles for the current company
        $roles = $company->roles()->get();

        return Inertia::render('Dashboard/Employees/AssignRoles', [
            'employee' => (new EmployeeResource($employee))->resolve(),
            'roles' => RoleResource::collection($roles)->resolve(),
        ]);
    }

    /**
     * Show the assign abilities form.
     */
    public function showAssignAbilities(User $employee)
    {
        // $this->authorize('update', $employee);

        $user = Auth::user();
        $company = $user->activeCompany;

        $employee->load('abilities');

        // Get all abilities for the current company
        $abilities = $company->abilities()->get();

        return Inertia::render('Dashboard/Employees/AssignAbilities', [
            'employee' => (new EmployeeResource($employee))->resolve(),
            'abilities' => AbilityResource::collection($abilities)->resolve(),
        ]);
    }

    /**
     * Show the assign departments form.
     */
    public function showAssigndepartments(User $employee)
    {
        // $this->authorize('update', $employee);

        $user = Auth::user();
        $company = $user->activeCompany;

        $employee->load('departments');

        // Get all abilities for the current company
        $departments = $company->departments()->active(column: 'departments.is_active')->get();

        return Inertia::render('Dashboard/Employees/AssignDepartments', [
            'employee' => (new EmployeeResource($employee))->resolve(),
            'departments' => DepartmentResource::collection($departments)->resolve(),
        ]);
    }

    /**
     * Show the assign jobTitles form.
     */
    public function showAssignJobTitles(User $employee)
    {
        // $this->authorize('update', $employee);

        $user = Auth::user();
        $company = $user->activeCompany;

        $employee->load('jobTitles');

        // Get all abilities for the current company
        $jobTitles = $company->jobTitles()->active(column: 'job_titles.is_active')->get();

        return Inertia::render('Dashboard/Employees/AssignJobTitles', [
            'employee' => (new EmployeeResource($employee))->resolve(),
            'jobTitles' => JobTitleResource::collection($jobTitles)->resolve(),
        ]);
    }

    /**
     * Assign roles to the employee.
     */
    public function assignRoles(Request $request, User $employee)
    {
        // $this->authorize('update', $employee);
        // dd($request->all());
        $request->validate([
            'roles' => 'required|array',
            'roles.*' => 'exists:roles,id',
        ]);

        $user = Auth::user();
        $company = $user->activeCompany;

        if (!$company) {
            return back()->with('error', 'No active company found');
        }

        // Get role IDs that belong to the current company
        $roleIds = $company->roles()->whereIn('roles.id', $request->input('roles', []))->pluck('roles.id')->toArray();

        $employee->syncRoles($roleIds, $company->id);

        return redirect()->route('dashboard.employees.edit', $employee)->with('success', 'Roles assigned successfully');
    }

    /**
     * Assign abilities to the employee.
     */
    public function assignAbilities(Request $request, User $employee)
    {
        // $this->authorize('update', $employee);
        // dd($request->all());
        $request->validate([
            'abilities' => 'required|array',
            'abilities.*' => 'required|exists:abilities,id',
        ]);

        $user = Auth::user();
        $company = $user->activeCompany;

        // Get abilities that belong to the current company
        $abilityIds = $company->abilities()->whereIn('id', $request->input('abilities', []))->pluck('id');

        // Sync abilities through the ability assignments table
        $this->abilityService->syncEmployeeAbilities($company, $employee, $abilityIds->toArray());

        return redirect()->route('dashboard.employees.show', $employee)->with('success', 'Abilities assigned successfully');
    }

    /**
     * Assign departments to the employee.
     */
    public function assignDepartments(Request $request, User $employee)
    {
        // $this->authorize('update', $employee);
        // dd($request->all());
        $request->validate([
            'departments' => 'required|array',
            'departments.*' => 'required|exists:departments,id',
        ]);

        $user = Auth::user();
        $company = $user->activeCompany;

        // Get abilities that belong to the current company
        $departmentsIds = $company->departments()->whereIn('id', $request->input('departments', []))->pluck('id');

        // Sync abilities through the ability assignments table
        $employee->departments()->syncWithPivotValues($departmentsIds->toArray(), ['company_id' => $company->id]);

        return redirect()->route('dashboard.employees.show', $employee)->with('success', 'Departments assigned successfully');
    }

    /**
     * Assign jobTitles to the employee.
     */
    public function assignJobTitles(Request $request, User $employee)
    {
        // $this->authorize('update', $employee);
        // dd($request->all());
        $request->validate([
            'jobTitles' => 'required|array',
            'jobTitles.*' => 'required|exists:job_titles,id',
        ]);

        $user = Auth::user();
        $company = $user->activeCompany;

        // Get abilities that belong to the current company
        $jobTitlesIds = $company->jobTitles()->whereIn('id', $request->input('jobTitles', []))->pluck('id');

        // Sync abilities through the ability assignments table
        $employee->jobTitles()->syncWithPivotValues($jobTitlesIds->toArray(), ['company_id' => $company->id]);

        return redirect()->route('dashboard.employees.show', $employee)->with('success', 'Job Titles assigned successfully');
    }
}
