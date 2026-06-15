<?php

namespace Database\Seeders;

use App\Models\Company;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class CompanyAndUserSeeder extends Seeder
{
    public function run(): void
    {
        // Company 1: TechNova Solutions
        $company1 = Company::create([
            'name' => 'TechNova Solutions',
            'industry' => 'Software Development',
            'slug' => Str::slug('TechNova Solutions'),
            'phone' => '+1-555-0198',
            'email' => 'contact@technova.com',
            'address' => '120 Innovation Drive, Silicon Valley, CA',
            'description' => 'A leading software development agency specializing in SaaS solutions.',
            'is_active' => true,
        ]);

        // Company 2: Apex Financial Services
        $company2 = Company::create([
            'name' => 'Apex Financial Services',
            'industry' => 'Finance & Accounting',
            'slug' => Str::slug('Apex Financial'),
            'phone' => '+1-555-0245',
            'email' => 'hello@apexfinancial.com',
            'address' => '400 Wall Street, Suite 500, New York, NY',
            'description' => 'Providing comprehensive financial planning and corporate accounting.',
            'is_active' => true,
        ]);

        // Company 3: GreenLeaf Retail
        $company3 = Company::create([
            'name' => 'GreenLeaf Retail',
            'industry' => 'Retail & E-commerce',
            'slug' => Str::slug('GreenLeaf Retail'),
            'phone' => '+1-555-0872',
            'email' => 'support@greenleaf.shop',
            'address' => '800 Commerce Blvd, Austin, TX',
            'description' => 'Fast-growing retail chain offering sustainable everyday products.',
            'is_active' => true,
        ]);

        // Creating Users
        $password = Hash::make('password123'); // common password for seeders

        // CEO Data
        $ceos = [
            ['name' => 'Sarah Connor', 'username' => 'sconnor', 'email' => 'sarah@technova.com', 'company' => $company1],
            ['name' => 'Michael Chen', 'username' => 'mchen', 'email' => 'michael@apexfinancial.com', 'company' => $company2],
            ['name' => 'Elena Rodriguez', 'username' => 'erodriguez', 'email' => 'elena@greenleaf.shop', 'company' => $company3],
        ];

        foreach ($ceos as $index => $ceoData) {
            $user = User::create([
                'name' => $ceoData['name'],
                'username' => $ceoData['username'],
                'email' => $ceoData['email'],
                'password' => $password,
                'active_company_id' => $ceoData['company']->id,
                'phone' => '555-000' . ($index + 1),
                'email_verified_at' => now(),
            ]);

            // Attach user to company_user pivot with role 'owner'
            $ceoData['company']->users()->attach($user->id, [
                'role' => 'owner',
                'is_active' => true,
            ]);
        }

        // Additional Employees for TechNova
        $techEmployees = [
            ['name' => 'David Smith', 'username' => 'dsmith', 'email' => 'david@technova.com'],
            ['name' => 'Jessica Taylor', 'username' => 'jtaylor', 'email' => 'jessica@technova.com'],
        ];

        foreach ($techEmployees as $idx => $empData) {
            $user = User::create([
                'name' => $empData['name'],
                'username' => $empData['username'],
                'email' => $empData['email'],
                'password' => $password,
                'active_company_id' => $company1->id,
                'phone' => '555-100' . ($idx + 1),
                'email_verified_at' => now(),
            ]);

            $company1->users()->attach($user->id, [
                'role' => 'employee',
                'is_active' => true,
            ]);
        }

        // Also a main admin user to test the system easily
        $adminUser = User::create([
            'name' => 'System Admin',
            'username' => 'admin',
            'email' => 'admin@admin.net',
            'password' => Hash::make('12345678'),
            'active_company_id' => $company1->id,
            'phone' => '1234567890',
            'email_verified_at' => now(),
        ]);

        $company1->users()->attach($adminUser->id, ['role' => 'owner', 'is_active' => true]);
        $company2->users()->attach($adminUser->id, ['role' => 'owner', 'is_active' => true]);
        $company3->users()->attach($adminUser->id, ['role' => 'owner', 'is_active' => true]);

        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId(null);
        \App\Models\Role::firstOrCreate(['name' => 'super-admin', 'guard_name' => 'web']);
        $adminUser->assignRole('super-admin'); // Assuming you have a super-admin role for testing

        Log::info('Company and User seeding completed successfully.');
        Log::debug([
            'admin_user' => $adminUser->toArray(),
            'admin_roles' => $adminUser->roles()->pluck('name'),
            'admin_permissions' => $adminUser->getAllPermissions()->pluck('name')->toArray(),
        ]);
    }
}
