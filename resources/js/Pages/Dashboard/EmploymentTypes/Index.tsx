import { Head, usePage } from '@inertiajs/react';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem, Auth } from '@/Types';
import { Button } from '@/Components/Ui/button';
import { EmploymentType } from '@/Types/employment-types';
import { PaginatedData } from '@/Types/global';
import EmploymentTypesStats from '@/Components/EmploymentTypes/EmploymentTypesStats';
import EmploymentTypesList from '@/Components/EmploymentTypes/EmploymentTypesList';
import CreateEmploymentTypeModal from '@/Components/EmploymentTypes/CreateEmploymentTypeModal';
import { Plus, Briefcase } from 'lucide-react';
import Filter from '@/Components/Shared/Filter';
import Pagination from '@/Components/Shared/Pagination';
import { useState } from 'react';
import EmptyResource from '@/Components/Shared/EmptyResource';
import usePermissions from '@/hooks/use-permissions';

const breadcrumbs: BreadcrumbItem[] = [
    {
        title: 'Dashboard',
        href: route('dashboard.index'),
    },
    {
        title: 'Employment Types',
        href: route('dashboard.employment-types.index'),
    },
];

interface EmploymentTypesIndexProps {
    employmentTypes: PaginatedData<EmploymentType>;
}

export default function EmploymentTypesIndex({ employmentTypes }: EmploymentTypesIndexProps) {
    const { user } = usePage().props.auth as Auth;
    const { can } = usePermissions();
    const employmentTypesData = employmentTypes?.data || [];
    const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);

    console.log('Employment Types:', employmentTypes);
    
    return (
        <AppLayout breadcrumbs={breadcrumbs}>
            <Head title="Employment Types - Administration" />

            <div className="flex-1 space-y-6 p-6">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
                            <Briefcase className="h-8 w-8" />
                            Employment Types
                        </h1>
                        <p className="text-muted-foreground">
                            Manage employment type categories for your organization
                        </p>
                    </div>

                    {can('employment-types.create') && (
                        <Button onClick={() => setIsCreateModalOpen(true)}>
                            <Plus className="mr-2 h-4 w-4" />
                            Add Employment Type
                        </Button>
                    )}
                </div>

                {/* Overview Cards */}
                {employmentTypes && (
                    <EmploymentTypesStats employmentTypes={employmentTypes} />
                )}

                {/* Filters and Search */}
                <Filter
                    routeName='dashboard.employment-types.index'
                    fields={{
                        search: { type: 'text', placeholder: 'Search by name or description' },
                        status: {
                            type: 'select', 
                            placeholder: 'Select Status', 
                            options: [
                                { value: 'all', label: 'All' },
                                { value: 'active', label: 'Active' },
                                { value: 'inactive', label: 'Inactive' },
                            ]
                        },
                    }}
                />

                {/* Employment Types List */}
                {employmentTypesData.length === 0 ? (
                    <EmptyResource 
                        icon={Briefcase}
                        title="No Employment Types Found"
                        description="Create a new employment type to get started."
                    />
                ) : employmentTypes ? (
                    <EmploymentTypesList 
                        employmentTypes={employmentTypesData} 
                    />
                ) : null}

                {/* Pagination */}
                <Pagination
                    meta={employmentTypes.meta}
                />
            </div>

            {/* Create Modal */}
            <CreateEmploymentTypeModal
                open={isCreateModalOpen}
                onOpenChange={setIsCreateModalOpen}
                onSuccess={() => {
                    setIsCreateModalOpen(false);
                }}
            />
        </AppLayout>
    );
}