<?php

namespace Database\Seeders;

use App\Models\Company;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class HrSeeder extends Seeder
{
    public function run(): void
    {
        $companies = Company::all();

        $employmentTypesData = [
            ['name' => 'Full-Time', 'description' => 'Standard 40 hours per week'],
            ['name' => 'Part-Time', 'description' => 'Up to 20 hours per week'],
            ['name' => 'Contractor', 'description' => 'Independent contractor agreement'],
        ];

        $contractTypesData = [
            ['name' => 'Permanent', 'description' => 'Indefinite duration employment contract'],
            ['name' => 'Fixed-Term', 'description' => 'Employment contract for a specifically defined period'],
            ['name' => 'Internship', 'description' => 'Short-term training contract'],
        ];

        foreach ($companies as $company) {
            // Create Employment Types
            $empTypes = [];
            foreach ($employmentTypesData as $data) {
                // Must insert instead of model create if no Model or just use DB
                $id = DB::table('employment_types')->insertGetId([
                    'company_id' => $company->id,
                    'name' => $data['name'],
                    'slug' => Str::slug($company->name . ' ' . $data['name']),
                    'description' => $data['description'],
                    'is_active' => true,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
                $empTypes[$data['name']] = DB::table('employment_types')->find($id);
            }

            // Create Contract Types
            $contTypes = [];
            foreach ($contractTypesData as $data) {
                $id = DB::table('contract_types')->insertGetId([
                    'company_id' => $company->id,
                    'name' => $data['name'],
                    'description' => $data['description'],
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
                $contTypes[$data['name']] = DB::table('contract_types')->find($id);
            }

            // Create Contracts & Compensation for each employee
            $users = $company->users()->get();

            foreach ($users as $user) {
                $jobTitle = $user->jobTitles()->first();
                $titleName = $jobTitle ? $jobTitle->title : 'Employee';

                $contractId = DB::table('contracts')->insertGetId([
                    'company_id' => $company->id,
                    'employee_id' => $user->id,
                    'employer_name' => $company->name,
                    'employer_address' => $company->address ?? 'HQ',
                    'employee_name' => $user->name,
                    'employee_address' => 'Home Address for ' . $user->name,
                    'position_title' => $titleName,
                    'duties_responsibilities' => 'Standard duties for ' . $titleName,
                    'employment_type' => $empTypes['Full-Time']->name,
                    'start_date' => now()->subMonths(rand(1, 24))->format('Y-m-d'),
                    'effective_date' => now()->subMonths(rand(1, 24))->format('Y-m-d'),
                    'additional_terms' => 'Standard non-compete clause applies.',
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);

                // Create compensation
                DB::table('contract_compensation')->insert([
                    'company_id' => $company->id,
                    'contract_id' => $contractId,
                    'base_salary' => $user->pivot->role === 'owner' ? 120000.00 : rand(50000, 90000),
                    'payment_schedule' => 'monthly',
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
            }
        }
    }
}
