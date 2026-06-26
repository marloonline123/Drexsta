import { Head, Link, usePage } from '@inertiajs/react';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem } from '@/Types';
import { Button } from '@/Components/Ui/button';
import { Department } from '@/Types/deparments';
import { PaginatedData } from '@/Types/global';
import { t } from 'i18next';
import DepartmentsStats from '@/Components/Departments/DepartmentsStats';
import DepartmentsList from '@/Components/Departments/DepartmentsList';
import { Plus } from 'lucide-react';
import Filter from '@/Components/Shared/Filter';
import Pagination from '@/Components/Shared/Pagination';
import usePermissions from '@/hooks/use-permissions';
import { Auth } from '@/Types';

const breadcrumbs: BreadcrumbItem[] = [
    {
        title: t('nav.dashboard'),
        href: route('dashboard.index'),
    },
    {
        title: t('nav.departments'),
        href: route('dashboard.departments.index'),
    },
];

interface DepartmentsIndexProps {
    departments: PaginatedData<Department>;
}

export default function DepartmentsIndex({ departments }: DepartmentsIndexProps) {
    const departmentsData = departments.data;
    const { user } = usePage().props.auth as Auth;
    const { can } = usePermissions();

    return (
        <AppLayout breadcrumbs={breadcrumbs}>
            <Head title="Departments - Admin" />

            <div className="flex-1 space-y-6 p-6">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-3xl font-bold tracking-tight">{t('departments')}</h1>
                        <p className="text-muted-foreground">
                            Manage organizational departments and their structures
                        </p>
                    </div>

                    {can('departments.create') && (
                        <Link href="/dashboard/departments/create">
                            <Button>
                                <Plus className="mr-2 h-4 w-4" />
                                Add Department
                            </Button>
                        </Link>
                    )}
                </div>

                {/* Overview Cards */}
                <DepartmentsStats departments={departments} />

                {/* Filters and Search */}
                <Filter
                    routeName='dashboard.departments.index'
                    fields={{
                        search: { type: 'text', placeholder: 'Search by name' },
                        status: {
                            type: 'select', placeholder: 'Select Status', options: [
                                { value: 'all', label: 'All' },
                                { value: 'active', label: 'Active' },
                                { value: 'inactive', label: 'Inactive' },
                            ]
                        },
                    }}
                />

                {/* Departments List */}
                <DepartmentsList departments={departmentsData} />

                {/* Pagination */}
                <Pagination
                    meta={departments.meta}
                />
            </div>
        </AppLayout>
    );
}