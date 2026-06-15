<?php

namespace Database\Seeders;

use App\Models\Company;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class PayrollSeeder extends Seeder
{
    public function run(): void
    {
        $companies = Company::all();

        foreach ($companies as $company) {
            $users = $company->users()->get();
            $adminUser = $users->where('username', 'admin')->first() ?? $users->first();

            // Create Payment Methods
            $paymentMethodId = DB::table('payment_methods')->insertGetId([
                'company_id' => $company->id,
                'name' => 'Bank Transfer',
                'slug' => Str::slug($company->name . ' Bank Transfer'),
                'is_active' => true,
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            // Create a Payroll for last month
            $startOfLastMonth = now()->subMonth()->startOfMonth();
            $endOfLastMonth = now()->subMonth()->endOfMonth();

            $payrollId = DB::table('payrolls')->insertGetId([
                'company_id' => $company->id,
                'period_start' => $startOfLastMonth->format('Y-m-d'),
                'period_end' => $endOfLastMonth->format('Y-m-d'),
                'processed_at' => now()->subMonth()->endOfMonth()->addDays(2),
                'status' => 'completed',
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            foreach ($users as $index => $user) {
                // Employee Bank
                DB::table('employee_banks')->insert([
                    'company_id' => $company->id,
                    'employee_id' => $user->id,
                    'bank_name' => 'Global Bank Inc.',
                    'account_number' => '1000' . rand(100000, 999999),
                    'iban' => 'US12GLBK' . rand(100000000, 999999999),
                    'swift_code' => 'GLBKUS33',
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);

                // User Payment Data
                DB::table('user_payment_data')->insert([
                    'company_id' => $company->id,
                    'employee_id' => $user->id,
                    'payment_method_id' => $paymentMethodId,
                    'custom_details' => json_encode(['account' => 'Primary Bank Account']),
                    'is_active' => true,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);

                $grossSalary = rand(4000, 10000); // Random monthly salary
                $tax = $grossSalary * 0.20;
                $netSalary = $grossSalary - $tax;

                // Payslip
                $payslipId = DB::table('payslips')->insertGetId([
                    'company_id' => $company->id,
                    'employee_id' => $user->id,
                    'payroll_id' => $payrollId,
                    'processed_by' => $adminUser->id,
                    'gross_salary' => $grossSalary,
                    'net_salary' => $netSalary,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);

                // Bonus
                $bonusId = DB::table('bonuses')->insertGetId([
                    'company_id' => $company->id,
                    'employee_id' => $user->id,
                    'created_by' => $adminUser->id,
                    'action_by' => $adminUser->id,
                    'amount' => $grossSalary,
                    'reason' => 'Basic Salary',
                    'status' => 'approved',
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);

                // Fine (Tax)
                $fineId = DB::table('fines')->insertGetId([
                    'company_id' => $company->id,
                    'employee_id' => $user->id,
                    'created_by' => $adminUser->id,
                    'action_by' => $adminUser->id,
                    'amount' => $tax,
                    'reason' => 'Income Tax',
                    'status' => 'approved',
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);

                // Payslip Items (Earnings and Deductions)
                DB::table('payslip_items')->insert([
                    [
                        'company_id' => $company->id,
                        'payslip_id' => $payslipId,
                        'itemable_type' => 'App\Models\Bonuse', // Or App\Models\Bonus
                        'itemable_id' => $bonusId,
                        'amount' => $grossSalary,
                        'direction' => 'credit',
                        'description' => 'Basic Salary',
                        'created_at' => now(),
                        'updated_at' => now()
                    ],
                    [
                        'company_id' => $company->id,
                        'payslip_id' => $payslipId,
                        'itemable_type' => 'App\Models\Fine',
                        'itemable_id' => $fineId,
                        'amount' => $tax,
                        'direction' => 'debit',
                        'description' => 'Income Tax Deduction',
                        'created_at' => now(),
                        'updated_at' => now()
                    ],
                ]);

                // Optional: Loans
                if ($index % 4 == 0) {
                    $loanId = DB::table('loans')->insertGetId([
                        'company_id' => $company->id,
                        'employee_id' => $user->id,
                        'created_by' => $adminUser->id,
                        'action_by' => $adminUser->id,
                        'total_amount' => 2000,
                        'installment_amount' => 200,
                        'total_installments' => 10,
                        'remaining_installments' => 9,
                        'status' => 'approved',
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);

                    DB::table('loan_payments')->insert([
                        'company_id' => $company->id,
                        'employee_id' => $user->id,
                        'loan_id' => $loanId,
                        'payslip_id' => $payslipId,
                        'amount' => 200,
                        'payment_date' => now()->subDays(5),
                        'source' => 'payroll',
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);
                }
            }
        }
    }
}
