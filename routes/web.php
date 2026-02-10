<?php

use App\Http\Controllers\Dashboard\AbilitiesController;
use App\Http\Controllers\Dashboard\ApprovalPolicyController;
use App\Http\Controllers\Dashboard\CompanyController;
use App\Http\Controllers\Dashboard\DepartmentController;
use App\Http\Controllers\Dashboard\Employee\EmployeeActionsController;
use App\Http\Controllers\Dashboard\Employee\EmployeeExcelController;
use App\Http\Controllers\Dashboard\Employee\EmployeesResourceController;
use App\Http\Controllers\Dashboard\Employee\UpdateEmployeePasswordController;
use App\Http\Controllers\Dashboard\EmploymentTypeController;
use App\Http\Controllers\Dashboard\JobApplicationController;
use App\Http\Controllers\Dashboard\JobPostingController as AdminJobPostingController;
use App\Http\Controllers\Dashboard\JobRequisitionController;
use App\Http\Controllers\Dashboard\JobTitleController;
use App\Http\Controllers\Dashboard\MyAttendanceController;
use App\Http\Controllers\Dashboard\MyDashboardController;
use App\Http\Controllers\Dashboard\MyLeavesController;
use App\Http\Controllers\Dashboard\MyLoansController;
use App\Http\Controllers\Dashboard\MyPayrollController;
use App\Http\Controllers\Dashboard\PaymentMethodController;
use App\Http\Controllers\Dashboard\RolesController;
use App\Http\Controllers\Public\JobPostingController;
use App\Http\Controllers\Profile\PasswordController;
use App\Http\Controllers\Profile\ProfileController;
use App\Http\Controllers\SelectCompanyController;
use App\Http\Controllers\Public\PublicPagesController;
use App\Models\Permission;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Inertia\Inertia;

Route::get('/test', function () {
    $user = Auth::user();
    $allPer = Permission::get()->pluck('id')->toArray();

    $user->sync($allPer, $user->active_company_id);

    return $user->permissions;
});

Route::redirect('/', '/dashboard')->name('home');

Route::middleware(['auth', 'verified'])->group(function () {
    // Route::get('/dashboard', function () {
    //     return Inertia::render('dashboard');
    // })->name('dashboard');
    Route::prefix('dashboard')->name('dashboard.')->middleware('hasActiveCompany')->group(function () {

        // Main dashboard page
        Route::get('/', [MyDashboardController::class, 'index'])->name('index');

        // Companies
        Route::resource('companies', CompanyController::class);
        
        // Departments
        Route::resource('departments', DepartmentController::class);

        // Employment Types
        Route::apiResource('employment-types', EmploymentTypeController::class);
        
        // Job Titles
        Route::apiResource('job-titles', JobTitleController::class);

        // Roles
        Route::get('roles/permissions', [RolesController::class, 'permissions'])->name('roles.permissions');
        Route::apiResource('roles', RolesController::class);
        
        // Abilities
        Route::apiResource('abilities', AbilitiesController::class);
        
        // Approval Policies
        Route::get('approval-policies', [ApprovalPolicyController::class, 'index'])->name('approval-policies.index');
        Route::patch('approval-policies/{approvalPolicy}', [ApprovalPolicyController::class, 'update'])->name('approval-policies.update');
        
        // Job Requisitions
        Route::resource('job-requisitions', JobRequisitionController::class);
        
        // Job Postings
        Route::resource('job-postings', AdminJobPostingController::class);
        Route::patch('job-postings/{jobPosting}/status', [AdminJobPostingController::class, 'updateStatus'])->name('job-postings.update-status');

        // Job Applications
        Route::resource('job-applications', JobApplicationController::class)->except(['create', 'store']);

        // Payment Methods
        Route::resource('payment-methods', PaymentMethodController::class);

        // Employees
        Route::resource('employees', EmployeesResourceController::class);
        Route::patch('employees/{employee}/update-password', [UpdateEmployeePasswordController::class, 'updatePassword'])->name('employees.update-password');
        Route::get('employees/{employee}/assign-roles', [EmployeeActionsController::class, 'showAssignRoles'])->name('employees.assign-roles');
        Route::get('employees/{employee}/assign-abilities', [EmployeeActionsController::class, 'showAssignAbilities'])->name('employees.assign-abilities');
        Route::get('employees/{employee}/assign-departments', [EmployeeActionsController::class, 'showAssigndepartments'])->name('employees.assign-departments');
        Route::get('employees/{employee}/assign-jobTitles', [EmployeeActionsController::class, 'showAssignJobTitles'])->name('employees.assign-jobTitles');
        Route::post('employees/{employee}/assign-roles', [EmployeeActionsController::class, 'assignRoles'])->name('employees.assign-roles.store');
        Route::post('employees/{employee}/assign-abilities', [EmployeeActionsController::class, 'assignAbilities'])->name('employees.assign-abilities.store');
        Route::post('employees/{employee}/assign-departments', [EmployeeActionsController::class, 'assigndepartments'])->name('employees.assign-departments.store');
        Route::post('employees/{employee}/assign-jobTitles', [EmployeeActionsController::class, 'assignJobTitles'])->name('employees.assign-jobTitles.store');
        Route::get('employees/export', [EmployeeExcelController::class, 'export'])->name('employees.export');
        Route::post('employees/import', [EmployeeExcelController::class, 'import'])->name('employees.import');

        // Profile Management
        Route::get('profile', [ProfileController::class, 'edit'])->name('profile.edit');
        Route::patch('profile', [ProfileController::class, 'update'])->name('profile.update');
        Route::delete('profile', [ProfileController::class, 'destroy'])->name('profile.destroy');
        Route::get('profile/password', [PasswordController::class, 'edit'])->name('profile.password.edit');
        Route::put('profile/password', [PasswordController::class, 'update'])
            ->middleware('throttle:6,1')
            ->name('profile.password.update');
        Route::get('profile/payment-data', [ProfileController::class, 'editPaymentData'])->name('profile.payment-data.edit');
        Route::patch('profile/payment-data', [ProfileController::class, 'updatePaymentData'])->name('profile.payment-data.update');
        Route::get('profile/appearance', function () {
            return Inertia::render('Profile/Appearance');
        })->name('profile.appearance');

        // Employee Pages
        Route::get('my-attendance', [MyAttendanceController::class, 'index'])->name('my-attendance.index');
        Route::get('my-leaves', [MyLeavesController::class, 'index'])->name('my-leaves.index');
        Route::get('my-payroll', [MyPayrollController::class, 'index'])->name('my-payroll.index');
        Route::get('my-loans', [MyLoansController::class, 'index'])->name('my-loans.index');
    });

    Route::get('select-company', [SelectCompanyController::class, 'select'])->name('select-company.show');
    Route::post('select-company/{company}', [SelectCompanyController::class, 'save'])->name('select-company.save');
    
    // HRM Routes
    Route::prefix('hrm')->group(function () {
        Route::get('employees', function () {
            return Inertia::render('hrm/employees');
        })->name('hrm.employees');
        
        Route::get('attendance', function () {
            return Inertia::render('hrm/attendance');
        })->name('hrm.attendance');
        
        Route::get('payroll', function () {
            return Inertia::render('hrm/payroll');
        })->name('hrm.payroll');
        
        Route::get('leaves', function () {
            return Inertia::render('hrm/leaves');
        })->name('hrm.leaves');
        
        Route::get('banks', function () {
            return Inertia::render('hrm/banks');
        })->name('hrm.banks');
    });
    
    // Administration Routes
    Route::prefix('admin')->group(function () {
        Route::get('security', function () {
            return Inertia::render('admin/security');
        })->name('admin.security');
        
        Route::get('users', function () {
            return Inertia::render('admin/users');
        })->name('admin.users');
    });
});

// Public Pages
Route::get('{company}/about', [PublicPagesController::class, 'about'])->name('about');
Route::get('{company}/contact', [PublicPagesController::class, 'contact'])->name('contact');
Route::post('{company}/contact', [PublicPagesController::class, 'storeContactForm'])->name('contact.store');


// Public Job Postings Routes
Route::get('jobs/{company}', [JobPostingController::class, 'index'])->name('jobs.index');
Route::get('jobs/{company}/{jobPosting}', [JobPostingController::class, 'show'])->name('jobs.show');
Route::get('jobs/{company}/{jobPosting}/apply', [JobPostingController::class, 'apply'])->name('jobs.apply');
Route::post('jobs/{company}/{jobPosting}/apply', [JobPostingController::class, 'storeApplication'])->name('jobs.apply.store');
Route::get('jobs/{company}/{jobPosting}/success/{applicationNumber}', [JobPostingController::class, 'applicationSuccess'])->name('jobs.apply.success');
Route::get('applications/{company}/{token}/edit', [JobPostingController::class, 'editApplication'])->name('applications.edit');
Route::put('applications/{company}/{token}', [JobPostingController::class, 'updateApplication'])->name('applications.update');

require __DIR__.'/settings.php';
require __DIR__.'/auth.php';