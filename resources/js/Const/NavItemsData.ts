import { t } from "i18next";
import { type NavItem } from '@/Types';
import {
    LayoutGrid,
    Building,
    Users,
    Clock,
    Calculator,
    Calendar,
    CreditCard,
    Briefcase,
    BadgeCheck,
    CheckCheck,
    Shield,
    Crown,
    Zap,
    UserCheck,
    Settings
} from 'lucide-react';

const mainNavItems: NavItem[] = [
    {
        title: 'nav.dashboard',
        href: route('dashboard.index'),
        icon: LayoutGrid,
        permission: null,
    },
    {
        title: 'nav.myAttendance',
        href: route('dashboard.my-attendance.index'),
        icon: Clock,
        permission: null,
    },
    {
        title: 'nav.myLeaves',
        href: route('dashboard.my-leaves.index'),
        icon: Calendar,
        permission: null,
    },
    {
        title: 'nav.myPayroll',
        href: route('dashboard.my-payroll.index'),
        icon: Calculator,
        permission: null,
    },
    {
        title: 'nav.myLoans',
        href: route('dashboard.my-loans.index'),
        icon: CreditCard,
        permission: null,
    },
];

const adminstrationNavItems: NavItem[] = [
    {
        title: 'nav.companies',
        href: route('dashboard.companies.index'),
        icon: Building,
        permission: 'companies.view',
    },
];


const hrmNavItems: NavItem[] = [
    {
        title: 'nav.employees',
        href: route('dashboard.employees.index'),
        icon: Users,
        permission: 'employees.view',
    },
    {
        title: 'nav.departments',
        href: route('dashboard.departments.index'),
        icon: Building,
        permission: 'departments.view',
    },
    {
        title: 'nav.attendance',
        href: '/hrm/attendance',
        icon: Clock,
        permission: 'attendance.view',
    },
    {
        title: 'nav.payroll',
        href: '/hrm/payroll',
        icon: Calculator,
        permission: 'payroll.view',
    },
    {
        title: 'nav.leaves',
        href: '/hrm/leaves',
        icon: Calendar,
        permission: 'leaves.view',
    },
    {
        title: 'nav.banks',
        href: '/hrm/banks',
        icon: CreditCard,
        permission: 'employees.view',
    },
];

const adminNavItems: NavItem[] = [
    {
        title: 'nav.employmentTypes',
        href: route('dashboard.employment-types.index'),
        icon: Briefcase,
        permission: 'employment-types.view',
    },
    {
        title: 'nav.jobTitles',
        href: route('dashboard.job-titles.index'),
        icon: BadgeCheck,
        permission: 'job-titles.view',
    },
    {
        title: 'nav.jobRequisitions',
        href: route('dashboard.job-requisitions.index'),
        icon: Briefcase,
        permission: 'job-requisitions.view',
    },
    {
        title: 'nav.jobPostings',
        href: route('dashboard.job-postings.index'),
        icon: Briefcase,
        permission: 'job-postings.view',
    },
    {
        title: 'nav.jobApplications',
        href: route('dashboard.job-applications.index'),
        icon: Briefcase,
        permission: 'job-applications.view',
    },
    {
        title: 'nav.approvalPolicies',
        href: route('dashboard.approval-policies.index'),
        icon: CheckCheck,
        permission: 'approval-policies.edit',
    },
    {
        title: 'nav.security',
        href: '/admin/security',
        icon: Shield,
        permission: 'roles.view',
    },
    {
        title: 'nav.roles',
        href: route('dashboard.roles.index'),
        icon: Crown,
        permission: 'roles.view',
    },
    {
        title: 'nav.abilities',
        href: route('dashboard.abilities.index'),
        icon: Zap,
        permission: 'abilities.view',
    },
    {
        title: 'nav.paymentMethods',
        href: route('dashboard.payment-methods.index'),
        icon: CreditCard,
        permission: 'payment-methods.view',
    },
    {
        title: 'nav.admin',
        href: '/admin/users',
        icon: UserCheck,
        permission: 'users.view',
    },
    {
        title: 'nav.settings',
        href: '/settings',
        icon: Settings,
        permission: 'settings.view',
    },
];

export const NAV_ITEMS_DATA = [
    {
        categoryName: 'nav.main',
        categoryIcon: null,
        // categoryIcon: LayoutGrid,
        items: mainNavItems,
    },
    {
        categoryName: 'nav.administration',
        categoryIcon: null,
        // categoryIcon: Building,
        items: adminstrationNavItems,
    },
    {
        categoryName: 'nav.hrm',
        categoryIcon: null,
        // categoryIcon: Users,
        items: hrmNavItems,
    },
    {
        categoryName: 'nav.admin',
        categoryIcon: null,
        // categoryIcon: Shield,
        items: adminNavItems,
    },
];