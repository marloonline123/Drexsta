import DepartmentsList from '@/Components/Departments/DepartmentsList';
import DepartmentsStats from '@/Components/Departments/DepartmentsStats';
import EmptyResource from '@/Components/Shared/EmptyResource';
import Filter from '@/Components/Shared/Filter';
import PageHeader from '@/Components/Shared/PageHeader';
import ResourceList from '@/Components/Shared/ResourceList';
import { buttonVariants } from '@/Components/Ui/button';
import usePermissions from '@/hooks/use-permissions';
import useTranslation from '@/Hooks/use-translation';
import AppLayout from '@/Layouts/AppLayout';
import { Auth, type BreadcrumbItem } from '@/Types';
import { Department } from '@/Types/deparments';
import { PaginatedData } from '@/Types/global';
import { Head, Link, usePage } from '@inertiajs/react';
import { Building, Plus } from 'lucide-react';

interface DepartmentsIndexProps {
    departments: PaginatedData<Department>;
}

export default function DepartmentsIndex({ departments }: DepartmentsIndexProps) {
    const departmentsData = departments?.data ?? [];
    const { user } = usePage().props.auth as Auth;
    const { translate } = useTranslation();
    const { can } = usePermissions();

    const breadcrumbs: BreadcrumbItem[] = [
        {
            title: translate('nav.dashboard'),
            href: route('dashboard.index'),
        },
        {
            title: translate('departments.title'),
            href: route('dashboard.departments.index'),
        },
    ];

    return (
        <AppLayout breadcrumbs={breadcrumbs}>
            <Head title="Departments - Administration" />

            <div className="flex-1 space-y-6 p-6">
                {/* Header */}
                <PageHeader
                    title={
                        <h1 className="flex items-center gap-2 text-3xl font-bold tracking-tight">
                            <Building className="h-8 w-8" />
                            {translate('departments.title')}
                        </h1>
                    }
                    description={translate('departments.description')}
                    action={
                        can('departments.create') && (
                            <Link href={route('dashboard.departments.create')} className={buttonVariants()}>
                                <Plus className="mr-2 h-4 w-4" />
                                {translate('departments.addTitle')}
                            </Link>
                        )
                    }
                />

                {/* Overview Cards */}
                <DepartmentsStats departments={departments} />

                {/* Filters and Search */}
                <Filter
                    routeName="dashboard.departments.index"
                    fields={{
                        search: { type: 'text', placeholder: translate('departments.searchPlaceholder') },
                        status: {
                            type: 'select',
                            placeholder: translate('main.select'),
                            options: [
                                { value: 'all', label: translate('main.all') },
                                { value: 'active', label: translate('main.active') },
                                { value: 'inactive', label: translate('main.inactive') },
                            ],
                        },
                    }}
                />

                {/* Departments List */}
                <ResourceList
                    dataLenght={departmentsData.length}
                    filled={<DepartmentsList departments={departmentsData} />}
                    empty={
                        <EmptyResource
                            icon={Building}
                            title={translate('main.noData')}
                            description={translate('departments.emptyDescription')}
                            action={
                                can('departments.create') && (
                                    <Link href={route('dashboard.departments.create')} className={buttonVariants()}>
                                        <Plus className="mr-2 h-4 w-4" />
                                        {translate('departments.addTitle')}
                                    </Link>
                                )
                            }
                        />
                    }
                    paginationData={departments?.meta}
                />
            </div>
        </AppLayout>
    );
}
