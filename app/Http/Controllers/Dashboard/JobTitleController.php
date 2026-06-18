<?php

namespace App\Http\Controllers\Dashboard;

use App\Http\Controllers\BaseController;
use App\Http\Requests\JobTitleRequest;
use App\Http\Resources\JobTitleResource;
use App\Models\JobTitle;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia;

class JobTitleController extends BaseController
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        $this->authorize('viewAny', JobTitle::class);
        $user = Auth::user();
        $company = $user->activeCompany;

        $jobTitles = JobTitle::search($request->get('search'), ['title', 'description'])
            ->filterBy('is_active', $request->has('status') ? $request->get('status') === 'active' : null)
            ->latest()
            ->paginate(12)
            ->withQueryString() ?? [];

        $totalJobTitles = $company?->jobTitles()->count() ?? 0;
        $jobTitlesCollection = JobTitleResource::collection($jobTitles)
            ->additional(['meta' => ['total_job_titles' => $totalJobTitles]]);

        return Inertia::render('Dashboard/JobTitles/Index', [
            'jobTitles' => $jobTitlesCollection,
        ]);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(JobTitleRequest $request)
    {
        $this->authorize('create', JobTitle::class);
        $data = $request->validated();
        $data['slug'] = generateSlug($data['title']);
        JobTitle::create($data);

        return back()->with('success', 'Job title created successfully');
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(JobTitleRequest $request, JobTitle $jobTitle)
    {
        $this->authorize('update', $jobTitle);
        $data = $request->validated();
        $jobTitle->update($data);

        return back()->with('success', 'Job title updated successfully');
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(JobTitle $jobTitle)
    {
        $this->authorize('delete', $jobTitle);
        $jobTitle->delete();

        return back()->with('success', 'Job title deleted successfully');
    }
}