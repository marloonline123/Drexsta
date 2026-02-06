<?php

namespace App\Http\Controllers\Dashboard;

use App\Enums\JobPostingStatus;
use App\Http\Controllers\BaseController;
use App\Http\Requests\JobPostingRequest;
use App\Http\Resources\EmploymentTypeResource;
use App\Http\Resources\JobPostingResource;
use App\Http\Resources\JobRequisitionResource;
use App\Http\Resources\JobTitleResource;
use App\Models\EmploymentType;
use App\Models\JobPosting;
use App\Models\JobRequisition;
use App\Models\JobTitle;
use App\Services\Business\JobPostingService;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Inertia\Inertia;

class JobPostingController extends BaseController
{
    function __construct(protected JobPostingService $jobPostingService) {}

    /**
     * Display a listing of the job postings.
     */
    public function index()
    {
        $this->authorize('viewAny', JobPosting::class);
        $postings = JobPosting::with(['jobRequisition.department', 'jobRequisition.jobTitle', 'jobTitle'])
            ->latest()
            ->paginate(12);

        return Inertia::render('Dashboard/JobPostings/Index', [
            'postings' => JobPostingResource::collection($postings),
        ]);
    }

    /**
     * Show the form for creating a new job posting.
     */
    public function create()
    {
        $this->authorize('create', JobPosting::class);
        $employmentTypes = EmploymentType::active()->get();
        $jobTitles = JobTitle::active()->get();
        $requisitions = JobRequisition::with(['department', 'jobTitle'])
            ->approved()
            ->get();

        return Inertia::render('Dashboard/JobPostings/Create', [
            'requisitions' => JobRequisitionResource::collection($requisitions)->resolve(),
            'employmentTypes' => EmploymentTypeResource::collection($employmentTypes)->resolve(),
            'jobTitles' => [],
        ]);
    }

    /**
     * Store a newly created job posting in storage.
     */
    public function store(JobPostingRequest $request)
    {
        $this->authorize('create', JobPosting::class);
        $data = $request->validated();
        $requisition = JobRequisition::findOrFail($data['job_requisition_id']);
        try {
            $this->jobPostingService->create($data, $requisition, $requisition->company);
            return redirect()->route('dashboard.job-postings.index')
                ->with('success', 'Job posting created successfully.');
        } catch (\Exception $e) {
            return redirect()->back()->with('error', $e->getMessage());
        }
    }

    /**
     * Display the specified job posting.
     */
    public function show(JobPosting $jobPosting)
    {
        $this->authorize('view', $jobPosting);
        $jobPosting->load(['jobRequisition.department', 'jobRequisition.jobTitle', 'jobRequisition.requester', 'company', 'employmentType', 'jobTitle']);

        return Inertia::render('Dashboard/JobPostings/Show', [
            'posting' => (new JobPostingResource($jobPosting))->resolve(),
        ]);
    }

    /**
     * Show the form for editing the specified job posting.
     */
    public function edit(JobPosting $jobPosting)
    {
        $this->authorize('update', $jobPosting);
        $jobPosting->load(['jobRequisition.department', 'jobRequisition.jobTitle', 'jobRequisition.requester', 'company']);
        $employmentTypes = EmploymentType::active()->get();
        $jobTitles = JobTitle::active()->get();
        $requisitions = JobRequisition::with(['department', 'jobTitle'])
            ->approved()
            ->get();

        return Inertia::render('Dashboard/JobPostings/Edit', [
            'posting' => (new JobPostingResource($jobPosting))->resolve(),
            'requisitions' => JobRequisitionResource::collection($requisitions)->resolve(),
            'employmentTypes' => EmploymentTypeResource::collection($employmentTypes)->resolve(),
            'jobTitles' => JobTitleResource::collection($jobTitles)->resolve(),
        ]);
    }

    /**
     * Update the specified job posting in storage.
     */
    public function update(JobPostingRequest $request, JobPosting $jobPosting)
    {
        $this->authorize('update', $jobPosting);
        $data = $request->validated();
        $jobPosting->update($data);

        return redirect()->back()->with('success', 'Job posting updated successfully.');
    }

    /**
     * Remove the specified job posting from storage.
     */
    public function destroy(JobPosting $jobPosting)
    {
        $this->authorize('delete', $jobPosting);
        $jobPosting->delete();

        return redirect()->route('dashboard.job-postings.index')
            ->with('success', 'Job posting deleted successfully.');
    }

    /**
     * Update the status of the job posting.
     */
    public function updateStatus(Request $request, JobPosting $jobPosting)
    {
        $this->authorize('update', $jobPosting);
        $request->validate([
            'status' => ['required', Rule::enum(JobPostingStatus::class)],
        ]);

        $jobPosting->update(['status' => $request->status]);

        return redirect()->back()->with('success', 'Job posting status updated successfully.');
    }
}