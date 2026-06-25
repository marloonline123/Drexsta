import { Head } from '@inertiajs/react';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem } from '@/Types';
import { Button } from '@/Components/Ui/button';
import { JobTitle } from '@/Types/job-titles';
import { PaginatedData } from '@/Types/global';
import JobTitlesList from '@/Components/JobTitles/JobTitlesList';
import CreateJobTitleModal from '@/Components/JobTitles/CreateJobTitleModal';
import { Plus, BadgeCheck } from 'lucide-react';
import Filter from '@/Components/Shared/Filter';
import { useState } from 'react';
import EmptyResource from '@/Components/Shared/EmptyResource';
import PageHeader from '@/Components/Shared/PageHeader';
import ResourceList from '@/Components/Shared/ResourceList';
import useTranslation from '@/Hooks/use-translation';
import usePermissions from '@/Hooks/use-permissions';


interface JobTitlesIndexProps {
    jobTitles: PaginatedData<JobTitle>;
}

export default function JobTitlesIndex({ jobTitles }: JobTitlesIndexProps) {
    const jobTitlesData = jobTitles?.data ?? [];
    const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
    const { translate } = useTranslation(); 
    const { can } = usePermissions();   

    const breadcrumbs: BreadcrumbItem[] = [
        {
            title: translate('nav.dashboard'),
            href: route('dashboard.index'),
        },
        {
            title: translate('jobTitles.title'),
            href: route('dashboard.job-titles.index'),
        },
    ];
    
    return (
        <AppLayout breadcrumbs={breadcrumbs}>
            <Head title="Job Titles - Administration" />

            <div className="flex-1 space-y-6 p-6">
                {/* Header */}
                <PageHeader
                    title={
                        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
                            <BadgeCheck className="h-8 w-8" />
                            {translate('jobTitles.title')}
                        </h1>
                    }
                    description={translate('jobTitles.description')}
                    action={
                        can('job-titles.create') && (
                            <Button onClick={() => setIsCreateModalOpen(true)}>
                                <Plus className="mr-2 h-4 w-4" />
                                {translate('jobTitles.addTitle')}
                            </Button>
                        )
                    }
                
                />

                {/* Filters and Search */}
                <Filter
                    routeName='dashboard.job-titles.index'
                    fields={{
                        search: { type: 'text', placeholder: translate('jobTitles.searchPlaceholder') },
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

                {/* Job Titles List */}
                <ResourceList
                    dataLenght={jobTitlesData.length}
                    filled={
                        <JobTitlesList 
                            jobTitles={jobTitlesData} 
                        />
                    }
                    empty={
                        <EmptyResource 
                            icon={BadgeCheck}
                            title={translate('common.noData')}
                            description={translate('jobTitles.emptyDescription')}
                        />
                    }
                    paginationData={jobTitles?.meta}
                />
            </div>

            {/* Create Modal */}
            <CreateJobTitleModal
                open={isCreateModalOpen}
                onOpenChange={setIsCreateModalOpen}
                onSuccess={() => {
                    setIsCreateModalOpen(false);
                }}
            />
        </AppLayout>
    );
}