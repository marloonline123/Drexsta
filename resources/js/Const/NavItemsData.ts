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
        title: t('nav.myDashboard'),
        href: route('dashboard.index'),
        icon: LayoutGrid,
        permission: null,
    },
    {
        title: t('nav.myAttendance'),
        href: route('dashboard.my-attendance.index'),
        icon: Clock,
        permission: null,
    },
    {
        title: t('nav.myLeaves'),
        href: route('dashboard.my-leaves.index'),
        icon: Calendar,
        permission: null,
    },
    {
        title: t('nav.myPayroll'),
        href: route('dashboard.my-payroll.index'),
        icon: Calculator,
        permission: null,
    },
    {
        title: t('nav.myLoans'),
        href: route('dashboard.my-loans.index'),
        icon: CreditCard,
        permission: null,
    },
];

const adminstrationNavItems: NavItem[] = [
    {
        title: t('nav.companyDashboard'),
        href: route('dashboard.index'),
        icon: LayoutGrid,
        permission: 'companies.view',
    },
    {
        title: t('nav.companies'),
        href: route('dashboard.companies.index'),
        icon: Building,
        permission: 'companies.view',
    },
];


const hrmNavItems: NavItem[] = [
    {
        title: t('nav.employees'),
        href: route('dashboard.employees.index'),
        icon: Users,
        permission: 'employees.view',
    },
    {
        title: t('nav.departments'),
        href: route('dashboard.departments.index'),
        icon: Building,
        permission: 'departments.view',
    },
    {
        title: t('nav.attendance'),
        href: '/hrm/attendance',
        icon: Clock,
        permission: 'attendance.view',
    },
    {
        title: t('nav.payroll'),
        href: '/hrm/payroll',
        icon: Calculator,
        permission: 'payroll.view',
    },
    {
        title: t('nav.leaves'),
        href: '/hrm/leaves',
        icon: Calendar,
        permission: 'leaves.view',
    },
    {
        title: t('nav.banks'),
        href: '/hrm/banks',
        icon: CreditCard,
        permission: 'employees.view',
    },
];

const adminNavItems: NavItem[] = [
    {
        title: t('nav.employmentTypes'),
        href: route('dashboard.employment-types.index'),
        icon: Briefcase,
        permission: 'employment-types.view',
    },
    {
        title: t('nav.jobTitles'),
        href: route('dashboard.job-titles.index'),
        icon: BadgeCheck,
        permission: 'job-titles.view',
    },
    {
        title: t('nav.jobRequisitions'),
        href: route('dashboard.job-requisitions.index'),
        icon: Briefcase,
        permission: 'job-requisitions.view',
    },
    {
        title: t('nav.jobPostings'),
        href: route('dashboard.job-postings.index'),
        icon: Briefcase,
        permission: 'job-postings.view',
    },
    {
        title: t('nav.jobApplications'),
        href: route('dashboard.job-applications.index'),
        icon: Briefcase,
        permission: 'job-applications.view',
    },
    {
        title: t('nav.approvalPolicies'),
        href: route('dashboard.approval-policies.index'),
        icon: CheckCheck,
        permission: 'approval-policies.edit',
    },
    {
        title: t('nav.security'),
        href: '/admin/security',
        icon: Shield,
        permission: 'roles.view',
    },
    {
        title: t('nav.roles'),
        href: route('dashboard.roles.index'),
        icon: Crown,
        permission: 'roles.view',
    },
    {
        title: t('nav.abilities'),
        href: route('dashboard.abilities.index'),
        icon: Zap,
        permission: 'abilities.view',
    },
    {
        title: t('nav.paymentMethods', 'Payment Methods'),
        href: route('dashboard.payment-methods.index'),
        icon: CreditCard,
        permission: 'payment-methods.view',
    },
    {
        title: t('nav.admin'),
        href: '/admin/users',
        icon: UserCheck,
        permission: 'users.view',
    },
    {
        title: t('nav.settings'),
        href: '/settings',
        icon: Settings,
        permission: 'settings.view',
    },
];

export const NAV_ITEMS_DATA = [
    {
        categoryName: t('nav.main'),
        // categoryIcon: LayoutGrid,
        categoryIcon: null,
        items: mainNavItems,
    },
    {
        categoryName: t('nav.administration'),
        categoryIcon: null,
        // categoryIcon: Building,
        items: adminstrationNavItems,
    },
    {
        categoryName: t('nav.hrm'),
        categoryIcon: null,
        // categoryIcon: Users,
        items: hrmNavItems,
    },
    {
        categoryName: t('nav.admin'),
        categoryIcon: null,
        // categoryIcon: Shield,
        items: adminNavItems,
    },
];