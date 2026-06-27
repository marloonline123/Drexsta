<?php

namespace App\Http\Controllers\Dashboard;

use App\Events\DepartmentCreated;
use App\Http\Controllers\BaseController;
use App\Http\Requests\DepartmentRequest;
use App\Http\Resources\DepartmentResource;
use App\Http\Resources\UserResource;
use App\Models\Department;
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia;

class DepartmentController extends BaseController
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $this->authorize('viewAny', Department::class);
        $user = Auth::user();
        $company = $user->activeCompany;
        $departments = Department::with('managerRelation', 'employees')
            ->search(request('search'), ['name', 'description'])
            ->filterBy('departments.is_active', request()->has('status') ? request('status') === 'active' : null)
            ->latest()
            ->paginate(12)
            ->withQueryString() ?? [];

        $activeDepartmentsCount = $company?->departments()->active()->count();
        $departments = DepartmentResource::collection($departments)->additional(['meta' => ['employees_count' => $company?->employees()->count(), 'active_departments_count' => $activeDepartmentsCount]]);

        return Inertia::render('Dashboard/Departments/Index', [
            'departments' => $departments,
        ]);
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        $this->authorize('create', Department::class);
        $user = Auth::user();
        $employees = $user->activeCompany?->users()->get() ?? [];

        return Inertia::render('Dashboard/Departments/Create', [
            'employees' => UserResource::collection($employees)->resolve(),
        ]);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(DepartmentRequest $request)
    {
        $this->authorize('create', Department::class);
        $user = Auth::user();
        $data = $request->validated();
        $data['slug'] = generateSlug($data['name']);
        $department = Department::create($data);
        $department->employees()->attach($data['manager_id'], ['role' => 'manager']);

        event(new DepartmentCreated($department));

        return redirect()->route('dashboard.departments.index')->with('success', __('departments.flash.created'));
    }

    /**
     * Display the specified resource.
     */
    public function show(Department $department)
    {
        $this->authorize('view', $department);
        $department->load('managerRelation', 'employees');
        return Inertia::render('Dashboard/Departments/Show', [
            'department' => (new DepartmentResource($department))->resolve(),
        ]);
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(Department $department)
    {
        $this->authorize('update', $department);
        $user = Auth::user();
        $department->load('managerRelation', 'employees');
        $employees = $user->activeCompany?->users()->get() ?? [];

        return Inertia::render('Dashboard/Departments/Edit', [
            'department' => (new DepartmentResource($department))->resolve(),
            'employees' => UserResource::collection($employees)->resolve()
        ]);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(DepartmentRequest $request, Department $department)
    {
        $this->authorize('update', $department);
        $data = $request->validated();
        $department->fill($data);

        $currentManagerId = $department->managerRelation()->first()?->id;
        if (isset($data['manager_id']) && $data['manager_id'] !== $currentManagerId) {
            // Remove old manager only
            $department->employees()
                ->wherePivot('role', 'manager')
                ->detach();

            // Attach the new manager
            $department->employees()->syncWithoutDetaching([
                $data['manager_id'] => [
                    'role' => 'manager',
                ],
            ]);
        }
        $department->save();

        return back()->with('success', __('departments.flash.updated'));
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Department $department)
    {
        $this->authorize('delete', $department);
        $department->delete();

        return redirect()->route('dashboard.departments.index')->with('success', __('departments.flash.deleted'));
    }
}
