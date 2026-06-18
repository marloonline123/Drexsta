<?php

namespace App\Http\Controllers\Dashboard;

use App\Http\Controllers\BaseController;
use App\Models\Attendance;
use App\Models\Leave;
use App\Models\Payslip;
use App\Models\User;
use Illuminate\Http\Request;
use Inertia\Inertia;

class MyDashboardController extends BaseController
{
    public function index(Request $request)
    {
        $user = $request->user();
        $companyId = $user->active_company_id;

        // Personal statistics for employees
        $personalStats = $this->getPersonalStats($user, $companyId);

        // Role-based additional stats
        $roleStats = $this->getRoleBasedStats($user, $companyId);

        // Recent activities
        $recentActivities = $this->getRecentActivities($user, $companyId);

        // Quick actions
        $quickActions = $this->getQuickActions($user);

        return Inertia::render('Dashboard/Dashboard', [
            'personalStats' => $personalStats,
            'roleStats' => $roleStats,
            'recentActivities' => $recentActivities,
            'quickActions' => $quickActions,
        ]);
    }

    private function getPersonalStats(User $user, int $companyId): array
    {
        // Today's attendance
        $todayAttendance = Attendance::where('employee_id', $user->id)
            ->where('company_id', $companyId)
            ->whereDate('date', today())
            ->first();

        // Leave balance
        $leaveBalance = Leave::where('employee_id', $user->id)
            ->where('company_id', $companyId)
            ->whereYear('created_at', now()->year)
            ->selectRaw("type, SUM(CASE WHEN status = 'approved' THEN CAST(julianday(end_date) - julianday(start_date) + 1 AS INTEGER) ELSE 0 END) as used_days")
            ->groupBy('type')
            ->get()
            ->pluck('used_days', 'type')
            ->toArray();

        // Monthly hours
        $monthlyHours = Attendance::where('employee_id', $user->id)
            ->where('company_id', $companyId)
            ->whereMonth('date', now()->month)
            ->sum('worked_hours');

        // Next payslip
        $nextPayslip = Payslip::where('employee_id', $user->id)
            ->where('company_id', $companyId)
            ->latest()
            ->first();

        return [
            'todayAttendance' => $todayAttendance,
            'leaveBalance' => $leaveBalance,
            'monthlyHours' => $monthlyHours,
            'nextPayslip' => $nextPayslip,
        ];
    }

    private function getRoleBasedStats(User $user, int $companyId): array
    {
        $stats = [];

        // If user has department management permissions, show department stats
        if ($user->can('departments.view')) {
            // Department stats would go here
            $stats['department'] = [];
        }

        // If user has employee management permissions, show team stats
        if ($user->can('employees.view')) {
            // Team stats would go here
            $stats['team'] = [];
        }

        return $stats;
    }

    private function getRecentActivities(User $user, int $companyId): array
    {
        // Recent attendances
        $recentAttendances = Attendance::where('user_id', $user->id)
            ->where('company_id', $companyId)
            ->latest()
            ->take(5)
            ->get();

        // Recent leaves
        $recentLeaves = Leave::where('employee_id', $user->id)
            ->where('company_id', $companyId)
            ->latest()
            ->take(5)
            ->get();

        return [
            'attendances' => $recentAttendances,
            'leaves' => $recentLeaves,
        ];
    }

    private function getQuickActions(User $user): array
    {
        return [
            [
                'title' => 'Clock In/Out',
                'url' => route('dashboard.my-attendance.index'),
                'icon' => 'clock',
            ],
            [
                'title' => 'Request Leave',
                'url' => route('dashboard.my-leaves.index'),
                'icon' => 'calendar',
            ],
            [
                'title' => 'View Profile',
                'url' => route('dashboard.profile.edit') . '?tab=payment-methods',
                'icon' => 'user',
            ],
            [
                'title' => 'View Payslip',
                'url' => route('dashboard.my-payroll.index'),
                'icon' => 'dollar-sign',
            ],
        ];
    }
}
