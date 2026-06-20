<?php

namespace App\Services\Business\CompanySetup;

use App\Models\Permission;
use App\Models\Role;

class PermissionRoleSetupService
{
    public function setupForCompany(int $companyId): void
    {
        $createdPermissions = $this->createPermissions();

        $this->createRolesAndAssignPermissions($createdPermissions, $companyId);
    }

    private function getDefaultPermissions(): array
    {
        return [
            // User Management
            'users.view',
            'users.create',
            'users.edit',
            'users.delete',

            // Role Management
            'roles.view',
            'roles.create',
            'roles.edit',
            'roles.delete',

            // Company Management
            'companies.view',
            'companies.create',
            'companies.edit',
            'companies.delete',

            // Employee Management
            'employees.view',
            'employees.create',
            'employees.edit',
            'employees.delete',
            'employees.assign-roles',
            'employees.assign-abilities',
            'employees.assign-job-titles',
            'employees.assign-departments',

            // Job Titles Management
            'job-titles.view',
            'job-titles.create',
            'job-titles.edit',
            'job-titles.delete',

            // Departments Management
            'departments.view',
            'departments.create',
            'departments.edit',
            'departments.delete',

            // Holidays Management
            'holidays.view',
            'holidays.create',
            'holidays.edit',
            'holidays.delete',

            // Leaves Management
            'leaves.view',
            'leaves.create',
            'leaves.edit',
            'leaves.delete',

            // Leave Types Management
            'leave-types.view',
            'leave-types.create',
            'leave-types.edit',
            'leave-types.delete',

            // Employment Types Management
            'employment-types.view',
            'employment-types.create',
            'employment-types.edit',
            'employment-types.delete',

            // Job Postings Management
            'job-postings.view',
            'job-postings.create',
            'job-postings.edit',
            'job-postings.delete',

            // Job Requesitions Management
            'job-requisitions.view',
            'job-requisitions.create',
            'job-requisitions.edit',
            'job-requisitions.delete',

            // Job Applications Management
            'job-applications.view',
            'job-applications.edit',
            'job-applications.delete',

            // Abilities Management
            'abilities.view',
            'abilities.create',
            'abilities.edit',
            'abilities.delete',

            // Approval Policies Management
            'approval-policies.edit',

            // Attendance
            'attendance.view',
            'attendance.manage',
            // Payroll
            'payroll.view',
            'payroll.manage',
            // Reports
            'reports.view',
            'reports.create',
            // Settings
            'settings.view',
            'settings.manage',

            // Payment Methods Management
            'payment-methods.view',
            'payment-methods.create',
            'payment-methods.edit',
            'payment-methods.delete',
        ];
    }

    private function createPermissions(): array
    {
        $permissions = $this->getDefaultPermissions();
        $createdPermissions = [];

        foreach ($permissions as $permission) {
            $createdPermissions[] = Permission::firstOrCreate(
                ['name' => $permission, 'guard_name' => 'web']
            );
        }

        return $createdPermissions;
    }

    private function createRolesAndAssignPermissions(array $permissions, int $companyId): void
    {
        // super-admin is global
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId(null);
        $adminRole = Role::firstOrCreate(['name' => 'super-admin', 'guard_name' => 'web']);
        $adminRole->syncPermissions($permissions);

        // company-scoped roles
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($companyId);
        $hrRole = Role::firstOrCreate(['name' => 'hr-manager', 'guard_name' => 'web', 'company_id' => $companyId]);
        $financeRole = Role::firstOrCreate(['name' => 'finance-manager', 'guard_name' => 'web', 'company_id' => $companyId]);
        $employeeRole = Role::firstOrCreate(['name' => 'employee', 'guard_name' => 'web', 'company_id' => $companyId]);

        // Assign permissions
        $hrRole->syncPermissions($this->filterPermissions($permissions, [
            'users.view',
            'users.create',
            'users.edit',
            'users.delete',
            'employees.view',
            'employees.create',
            'employees.edit',
            'employees.delete',
            'attendance.view',
            'attendance.manage',
            'reports.view',
            'employees.assign-roles',
            'roles.view',
            'roles.create',
            'roles.edit',
            'roles.delete',
            'job-titles.view',
            'job-titles.create',
            'job-titles.edit',
            'job-titles.delete',
            'departments.view',
            'departments.create',
            'departments.edit',
            'departments.delete',
            'holidays.view',
            'holidays.create',
            'holidays.edit',
            'holidays.delete',
            'leaves.view',
            'leaves.create',
            'leaves.edit',
            'leaves.delete',
            'leave-types.view',
            'leave-types.create',
            'leave-types.edit',
            'leave-types.delete',
            'employment-types.view',
            'employment-types.create',
            'employment-types.edit',
            'employment-types.delete',
            'job-postings.view',
            'job-postings.create',
            'job-postings.edit',
            'job-postings.delete',
            'job-requisitions.view',
            'job-requisitions.create',
            'job-requisitions.edit',
            'job-requisitions.delete',
            'job-applications.view',
            'job-applications.edit',
            'job-applications.delete',
            'abilities.view',
            'abilities.create',
            'abilities.edit',
            'abilities.delete',
            'approval-policies.edit',
            'payment-methods.view',
            'payment-methods.create',
            'payment-methods.edit',
            'payment-methods.delete',
        ]));

        $financeRole->syncPermissions($this->filterPermissions($permissions, [
            'payroll.view',
            'payroll.manage',
            'reports.view',
            'reports.create'
        ]));

        $employeeRole->syncPermissions($this->filterPermissions($permissions, [
            'employees.view',
            'attendance.view'
        ]));
    }

    private function filterPermissions(array $permissions, array $names): array
    {
        return collect($permissions)->filter(fn($p) => in_array($p->name, $names))->values()->all();
    }
}
