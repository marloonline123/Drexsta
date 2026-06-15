<?php

namespace App\Http\Controllers\Dashboard;

use App\Events\CompanyCreated;
use App\Http\Controllers\BaseController;
use App\Http\Requests\CompanyRequest;
use App\Http\Resources\CompanyResource;
use App\Models\Company;
use App\Services\Shared\FileService;
use Illuminate\Support\Facades\Auth;
use Inertia\Response;

class CompanyController extends BaseController
{
    public function __construct(protected FileService $fileService)
    {
    }

    /**
     * Display a listing of the companies.
     *
     * @return \Inertia\Response
     */
    public function index(): Response
    {
        // $this->authorize('viewAny', Company::class);
        $user = Auth::user();
        $companies = $user->ownedCompanies()
            ->with('employees')
            ->search(request('search'), ['name', 'industry', 'email', 'phone'])
            ->filterBy('companies.is_active', request()->has('status') ? request('status') === 'active' : null)
            ->latest()
            ->paginate(12)
            ->withQueryString();

        $employeesCount = $user->companies()
            ->withCount(['employees'])
            ->get()
            ->sum('employees_count');

        $companies = CompanyResource::collection($companies)->additional(['meta' => ['employees_count' => $employeesCount]]);
        return inertia()->render('Dashboard/Companies/Index', [
            'companies' => $companies,
        ]);
    }

    /**
     * Render the company creation form.
     *
     * @return \Inertia\Response
     */
    public function create(): Response
    {
        $this->authorize('create', Company::class);
        return inertia()->render('Dashboard/Companies/Create');
    }

    /**
     * Store a newly created Company.
     *
     * @param \App\Http\Requests\Admin\CompanyRequest $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function store(CompanyRequest $request)
    {
        $this->authorize('create', Company::class);
        $data = $request->validated();
        $data['slug'] = generateSlug($data['name']);
        if ($request->hasFile('logo_image')) {
            $data['logo_path'] = $this->fileService->storeImage($request->file('logo_image'), 'companies');
        }
        $company = Company::create($data);
        $company->users()->attach(Auth::id(), ['role' => 'owner', 'created_at' => now(), 'updated_at' => now()]);

        event(new CompanyCreated($company));

        return to_route('dashboard.companies.index')->with('success', 'Company created successfully.');
    }

    /**
     * Display the specified company.
     *
     * @param \App\Models\Company $company
     * @return \Inertia\Response
     */
    public function show(Company $company)
    {
        $this->authorize('view', $company);
        $company->load('employees');
        return inertia()->render('Dashboard/Companies/Show', [
            'company' => CompanyResource::make($company)->resolve()
        ]);
    }

    /**
     * Show the form for editing the specified company.
     *
     * @param \App\Models\Company $company
     * @return \Inertia\Response
     */
    public function edit(Company $company)
    {
        $this->authorize('update', $company);
        return inertia()->render('Dashboard/Companies/Edit', [
            'company' => CompanyResource::make($company)->resolve()
        ]);
    }

    /**
     * Update the specified company in storage.
     *
     * @param \Illuminate\Http\Request $request
     * @param \App\Models\Company $company
     * @return \Illuminate\Http\RedirectResponse
     */
    public function update(CompanyRequest $request, Company $company)
    {
        $this->authorize('update', $company);
        $data = $request->validated();
        if ($request->hasFile('logo_image')) {
            $data['logo_path'] = $this->fileService->storeImage($request->file('logo_image'), 'companies');
        }
        $company->update($data);

        return back()->with('success', 'Company updated successfully.');
    }

    /**
     * Remove the specified company from storage.
     *
     * @param \App\Models\Company $company
     * @return \Illuminate\Http\RedirectResponse
     */
    public function destroy(Company $company)
    {
        $this->authorize('delete', $company);
        $company->delete();
        return back()->with('success', 'Company deleted successfully.');
    }
}
