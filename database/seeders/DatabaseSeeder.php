<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        // 1. Create Core Data (Companies and Users)
        $this->call([
            CompanyAndUserSeeder::class ,
        ]);

        // 2. Setup Permissions and Roles for the created companies
        $this->call([
            PermissionSeeder::class ,
        ]);

        // 3. Setup Organization Structure (Departments, Job Titles, assigning users)
        $this->call([
            OrganizationSeeder::class ,
        ]);

        // 4. Setup HR Information (Contracts, Employment Types, Compensation)
        $this->call([
            HrSeeder::class ,
        ]);

        // 5. Setup Payroll & Financials (Banks, Payment Methods, Payrolls)
        $this->call([
            PayrollSeeder::class ,
        ]);

        // 6. Setup Operations Data (Attendance, Leaves, Performance Reviews)
        $this->call([
            OperationsSeeder::class ,
        ]);
    }
}