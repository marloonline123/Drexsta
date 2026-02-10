<?php

namespace Database\Seeders;

use App\Models\Company;
use Illuminate\Database\Seeder;
use App\Services\Business\CompanySetupService;
use App\Services\Business\CompanySetup\PermissionRoleSetupService;

class PermissionSeeder extends Seeder
{
    public function __construct(
        private PermissionRoleSetupService $permissionRoleSetupService
    ) {}
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Get all companies
        $companies = Company::all();
        
        // If no companies exist, create permissions without company_id
        if ($companies->isEmpty()) {
            return;
        }
        
        // Create permissions and roles for each company
        foreach ($companies as $company) {
            $this->permissionRoleSetupService->setupForCompany($company->id);
        }
    }
}