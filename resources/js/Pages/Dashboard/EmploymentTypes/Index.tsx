import { Head } from '@inertiajs/react';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem } from '@/Types';
import { Button } from '@/Components/Ui/button';
import { EmploymentType } from '@/Types/employment-types';
import { PaginatedData } from '@/Types/global';
import EmploymentTypesList from '@/Components/EmploymentTypes/EmploymentTypesList';
import CreateEmploymentTypeModal from '@/Components/EmploymentTypes/CreateEmploymentTypeModal';
import { Plus, Briefcase } from 'lucide-react';
import Filter from '@/Components/Shared/Filter';
import { useState } from 'react';
import EmptyResource from '@/Components/Shared/EmptyResource';
import PageHeader from '@/Components/Shared/PageHeader';
import ResourceList from '@/Components/Shared/ResourceList';
import useTranslation from '@/Hooks/use-translation';
import usePermissions from '@/hooks/use-permissions';

interface EmploymentTypesIndexProps {
    employmentTypes: PaginatedData<EmploymentType>;
}

export default function EmploymentTypesIndex({ employmentTypes }: EmploymentTypesIndexProps) {
    const employmentTypesData = employmentTypes?.data ?? [];
    const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
    const { translate } = useTranslation();
    const { can } = usePermissions();

    const breadcrumbs: BreadcrumbItem[] = [
        {
            title: translate('nav.dashboard'),
            href: route('dashboard.index'),
        },
        {
            title: translate('employment_types.title'),
            href: route('dashboard.employment-types.index'),
        },
    ];
    
    return (
        <AppLayout breadcrumbs={breadcrumbs}>
            <Head title="Employment Types - Administration" />

            <div className="flex-1 space-y-6 p-6">
                {/* Header */}
                <PageHeader
                    title={
                        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
                            <Briefcase className="h-8 w-8" />
                            {translate('employment_types.title')}
                        </h1>
                    }
                    description={translate('employment_types.description')}
                    action={
                        can('employment-types.create') && (
                            <Button onClick={() => setIsCreateModalOpen(true)}>
                                <Plus className="mr-2 h-4 w-4" />
                                {translate('employment_types.addType')}
                            </Button>
                        )
                    }
                />

                {/* Filters and Search */}
                <Filter
                    routeName='dashboard.employment-types.index'
                    fields={{
                        search: { type: 'text', placeholder: translate('employment_types.searchPlaceholder') },
                        status: {
                            type: 'select', 
                            placeholder: translate('main.select'), 
                            options: [
                                { value: 'all', label: translate('main.all') },
                                { value: 'active', label: translate('main.active') },
                                { value: 'inactive', label: translate('main.inactive') },
                            ]
                        },
                    }}
                />

                {/* Employment Types List */}
                <ResourceList
                    dataLenght={employmentTypesData.length}
                    filled={
                        <EmploymentTypesList 
                            employmentTypes={employmentTypesData} 
                        />
                    }
                    empty={
                        <EmptyResource 
                            icon={Briefcase}
                            title={translate('common.noData')}
                            description={translate('employment_types.emptyDescription')}
                        />
                    }
                    paginationData={employmentTypes?.meta}
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