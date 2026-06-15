<?php

namespace Database\Seeders;

use App\Models\Company;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class OperationsSeeder extends Seeder
{
    public function run(): void
    {
        $companies = Company::all();

        foreach ($companies as $company) {
            $users = $company->users()->get();
            $adminUser = $users->where('username', 'admin')->first() ?? $users->first();

            foreach ($users as $index => $user) {
                // Generate 5 days of attendance for each user
                for ($i = 1; $i <= 5; $i++) {
                    $date = now()->subDays($i);
                    $checkInHour = rand(8, 9);
                    $checkInMinute = rand(0, 59);
                    $checkOutHour = rand(17, 18);
                    $checkOutMinute = rand(0, 59);

                    $status = 'present';
                    if ($checkInHour == 9 && $checkInMinute > 15) {
                        $status = 'late';
                    }

                    DB::table('attendances')->insert([
                        'company_id' => $company->id,
                        'employee_id' => $user->id,
                        'date' => $date->format('Y-m-d'),
                        'check_in' => sprintf('%02d:%02d:00', $checkInHour, $checkInMinute),
                        'check_out' => sprintf('%02d:%02d:00', $checkOutHour, $checkOutMinute),
                        'worked_hours' => 8.00,
                        'status' => $status,
                        'source' => 'biometric',
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);
                }

                // Leaves
                if ($index % 3 == 0) {
                    DB::table('leaves')->insert([
                        'company_id' => $company->id,
                        'employee_id' => $user->id,
                        'type' => 'sick',
                        'start_date' => now()->subDays(10)->format('Y-m-d'),
                        'end_date' => now()->subDays(8)->format('Y-m-d'),
                        'reason' => 'Severe flu and fever',
                        'status' => 'approved',
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);
                }

                // Performance Reviews
                if ($index % 2 == 0) {
                    DB::table('performance_reviews')->insert([
                        'company_id' => $company->id,
                        'employee_id' => $user->id,
                        'review_type' => 'annual',
                        'rating' => rand(3, 5),
                        'notes' => 'Consistently meets expectations and shows great teamwork.',
                        'reviewed_by' => $adminUser->id,
                        'review_date' => now()->subMonths(2)->format('Y-m-d'),
                        'passed_probation' => true,
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);
                }
            }
        }
    }
}
