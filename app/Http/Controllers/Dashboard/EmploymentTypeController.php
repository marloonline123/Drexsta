<?php

namespace App\Http\Controllers\Dashboard;

use App\Http\Controllers\BaseController;
use App\Http\Requests\EmploymentTypeRequest;
use App\Http\Resources\EmploymentTypeResource;
use App\Models\EmploymentType;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia;

class EmploymentTypeController extends BaseController
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        $this->authorize('viewAny', EmploymentType::class);
        $user = Auth::user();
        $company = $user->activeCompany;

        $employmentTypes = EmploymentType::search($request->get('search'), ['name', 'description'])
            ->filterBy('is_active', $request->has('status') ? $request->get('status') === 'active' : null)
            ->latest()
            ->paginate(12)
            ->withQueryString() ?? [];

        $totalEmploymentTypes = $company?->employmentTypes()->count() ?? 0;
        $employmentTypesCollection = EmploymentTypeResource::collection($employmentTypes)
            ->additional(['meta' => ['total_employment_types' => $totalEmploymentTypes]]);

        return Inertia::render('Dashboard/EmploymentTypes/Index', [
            'employmentTypes' => $employmentTypesCollection,
        ]);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(EmploymentTypeRequest $request)
    {
        $this->authorize('create', EmploymentType::class);
        $data = $request->validated();
        $data['slug'] = generateSlug($data['name']);
        EmploymentType::create($data);

        return back()->with('success', __('employment_types.flash.created'));
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(EmploymentTypeRequest $request, EmploymentType $employmentType)
    {
        $this->authorize('update', $employmentType);
        $data = $request->validated();
        $employmentType->update($data);

        return back()->with('success', __('employment_types.flash.updated'));
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(EmploymentType $employmentType)
    {
        $this->authorize('delete', $employmentType);
        $employmentType->delete();

        return back()->with('success', __('employment_types.flash.deleted'));
    }
}
