import CreateJobTitleModal from '@/Components/JobTitles/CreateJobTitleModal';
import JobTitlesList from '@/Components/JobTitles/JobTitlesList';
import EmptyResource from '@/Components/Shared/EmptyResource';
import Filter from '@/Components/Shared/Filter';
import PageHeader from '@/Components/Shared/PageHeader';
import ResourceList from '@/Components/Shared/ResourceList';
import { Button } from '@/Components/Ui/button';
import usePermissions from '@/Hooks/use-permissions';
import useTranslation from '@/Hooks/use-translation';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem } from '@/Types';
import { PaginatedData } from '@/Types/global';
import { JobTitle } from '@/Types/job-titles';
import { Head } from '@inertiajs/react';
import { BadgeCheck, Plus } from 'lucide-react';
import { useState } from 'react';

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
            title: translate('job_titles.title'),
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
                        <h1 className="flex items-center gap-2 text-3xl font-bold tracking-tight">
                            <BadgeCheck className="h-8 w-8" />
                            {translate('job_titles.title')}
                        </h1>
                    }
                    description={translate('job_titles.description')}
                    action={
                        can('job-titles.create') && (
                            <Button onClick={() => setIsCreateModalOpen(true)}>
                                <Plus className="mr-2 h-4 w-4" />
                                {translate('job_titles.addTitle')}
                            </Button>
                        )
                    }
                />

                {/* Filters and Search */}
                <Filter
                    routeName="dashboard.job-titles.index"
                    fields={{
                        search: { type: 'text', placeholder: translate('job_titles.searchPlaceholder') },
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

                {/* Job Titles List */}
                <ResourceList
                    dataLenght={jobTitlesData.length}
                    filled={<JobTitlesList jobTitles={jobTitlesData} />}
                    empty={
                        <EmptyResource
                            icon={BadgeCheck}
                            title={translate('main.noData')}
                            description={translate('job_titles.emptyDescription')}
                            action={
                                can('job-titles.create') && (
                                    <Button onClick={() => setIsCreateModalOpen(true)}>
                                        <Plus className="mr-2 h-4 w-4" />
                                        {translate('job_titles.addTitle')}
                                    </Button>
                                )
                            }
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
