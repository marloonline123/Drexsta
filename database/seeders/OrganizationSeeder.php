<?php

namespace Database\Seeders;

use App\Models\Company;
use App\Models\Department;
use App\Models\JobTitle;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Str;

class OrganizationSeeder extends Seeder
{
    public function run(): void
    {
        $companies = Company::all();

        $departmentsData = [
            ['name' => 'Engineering', 'description' => 'Software and QA Engineering', 'budget' => 500000.00],
            ['name' => 'Sales', 'description' => 'Global Sales and Marketing', 'budget' => 250000.00],
            ['name' => 'Human Resources', 'description' => 'Talent acquisition and management', 'budget' => 100000.00],
            ['name' => 'Finance', 'description' => 'Accounting and Financial Planning', 'budget' => 150000.00],
        ];

        $jobTitlesData = [
            ['title' => 'Software Engineer', 'description' => 'Develops and maintains applications.'],
            ['title' => 'Senior Software Engineer', 'description' => 'Leads application development and architecture.'],
            ['title' => 'Sales Executive', 'description' => 'Drives revenue through client acquisition.'],
            ['title' => 'HR Manager', 'description' => 'Oversees employee relations and recruitment.'],
            ['title' => 'Accountant', 'description' => 'Manages corporate financial records.'],
            ['title' => 'CEO', 'description' => 'Chief Executive Officer'],
        ];

        foreach ($companies as $company) {
            // Create Departments
            $departments = [];
            foreach ($departmentsData as $data) {
                $departments[$data['name']] = Department::create([
                    'company_id' => $company->id,
                    'name' => $data['name'],
                    'slug' => Str::slug($company->name . ' ' . $data['name']),
                    'description' => $data['description'],
                    'annual_budget' => $data['budget'],
                    'is_active' => true,
                ]);
            }

            // Create Job Titles
            $jobTitles = [];
            foreach ($jobTitlesData as $data) {
                $jobTitles[$data['title']] = JobTitle::create([
                    'company_id' => $company->id,
                    'title' => $data['title'],
                    'slug' => Str::slug($company->name . ' ' . $data['title']),
                    'description' => $data['description'],
                    'is_active' => true,
                ]);
            }

            // Assign Job Titles and Departments to users in this company
            $users = $company->users()->get();

            foreach ($users as $index => $user) {
                $pivotData = ['company_id' => $company->id];

                // If it's an owner, make them CEO and assign to all departments but specific one if possible
                if ($user->pivot->role === 'owner') {
                    $user->jobTitles()->syncWithoutDetaching([$jobTitles['CEO']->id => $pivotData]);
                    // CEO might not be in a specific department, but let's assign to Finance
                    $user->departments()->syncWithoutDetaching([
                        $departments['Finance']->id => array_merge($pivotData, ['role' => 'manager'])
                    ]);
                }
                else {
                    // Assign random department and job title
                    if ($index % 2 == 0) {
                        $user->jobTitles()->syncWithoutDetaching([$jobTitles['Software Engineer']->id => $pivotData]);
                        $user->departments()->syncWithoutDetaching([
                            $departments['Engineering']->id => array_merge($pivotData, ['role' => 'employee'])
                        ]);
                    }
                    else {
                        $user->jobTitles()->syncWithoutDetaching([$jobTitles['Sales Executive']->id => $pivotData]);
                        $user->departments()->syncWithoutDetaching([
                            $departments['Sales']->id => array_merge($pivotData, ['role' => 'employee'])
                        ]);
                    }
                }
            }
        }
    }
}
