<?php

namespace App\Services\Business;

use App\Models\Company;
use App\Models\JobPosting;
use App\Models\JobRequisition;

class JobPostingService
{
    public function create(array $data = [], JobRequisition $requisition, Company $company): JobPosting
    {
        // Create the job posting with data from requisition
        $posting = JobPosting::create($data + [
            'company_id' => $company->id,
            'job_title_id' => $requisition->job_title_id,
            'job_requisition_id' => $requisition->id,
            'number' => $this->generateJobPostingNumber($company->id),
            'title' => $requisition->jobTitle->title,
            'slug' => generateUniqueSlug(JobPosting::class, $data['title'] ?? $requisition->jobTitle->title),
            'description' => $requisition->job_description,
            'requirements' => $requisition->requirements,
            'min_salary' => $requisition->min_salary,
            'max_salary' => $requisition->max_salary,
            'employment_type_id' => $requisition->employment_type_id,
        ]);

        return $posting;
    }

    private function generateJobPostingNumber(int $companyId): string
    {
        $prefix = 'CMP_' . $companyId . '_' . now()->format('Ymd') . '_JobPost-';
        $lastJobPosting = JobPosting::where('number', 'like', $prefix . '%')
            ->orderBy('id', 'desc')
            ->first();

        if ($lastJobPosting) {
            $lastJobPostingNumber = str_replace($prefix, '', $lastJobPosting->number);
            $newNumber = $lastJobPostingNumber + 1;
        } else {
            $newNumber = 1;
        }

        return $prefix . str_pad($newNumber, 4, '0', STR_PAD_LEFT);
    }
}