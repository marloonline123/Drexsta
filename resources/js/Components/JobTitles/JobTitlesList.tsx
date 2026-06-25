import { Button } from '@/Components/Ui/button';
import { Card, CardContent } from '@/Components/Ui/card';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/Components/Ui/dropdown-menu';
import useTranslation from '@/Hooks/use-translation';
import { JobTitle } from '@/Types/job-titles';
import { BadgeCheck, Edit, Eye, MoreHorizontal, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { DataTable } from '../Shared/DataTable';
import IsActiveTogglar from '../Shared/IsActiveTogglar';
import { StatusBadge } from '../Shared/StatusBadge';
import DeleteJobTitleModal from './DeleteJobTitleModal';
import EditJobTitleModal from './EditJobTitleModal';
import ViewJobTitleModal from './ViewJobTitleModal';
import usePermissions from '@/Hooks/use-permissions';

interface JobTitlesListProps {
    jobTitles: JobTitle[];
}

export default function JobTitlesList({ jobTitles }: JobTitlesListProps) {
    const [editingJobTitle, setEditingJobTitle] = useState<JobTitle | null>(null);
    const [deletingJobTitle, setDeletingJobTitle] = useState<JobTitle | null>(null);
    const [viewingJobTitle, setViewingJobTitle] = useState<JobTitle | null>(null);
    const { translate } = useTranslation();
    const { can } = usePermissions();   


    const columns = [
        {
            header: translate('jobTitles.headers.title'),
            accessorKey: 'title' as keyof JobTitle,
            cell: (jobTitle: JobTitle) => (
                <div className="flex items-center gap-2">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
                        <BadgeCheck className="h-4 w-4 text-primary" />
                    </div>
                    <div>
                        <div className="font-medium">{jobTitle.title}</div>
                        {/* <div className="text-sm text-muted-foreground">{jobTitle.slug}</div> */}
                    </div>
                </div>
            ),
        },
        {
            header: translate('jobTitles.headers.status'),
            cell: (jobTitle: JobTitle) => (
                <IsActiveTogglar route={route('dashboard.job-titles.toggle-status', jobTitle)} children={<StatusBadge status={!!jobTitle.is_active} />} />
            ),
        },
        { header: translate('jobTitles.headers.date'), accessorKey: 'created_at' as keyof JobTitle },
        {
            header: translate('jobTitles.headers.actions'),
            className: 'text-center',
            cell: (jobTitle: JobTitle) => (
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="ghost" className="h-8 w-8 p-0">
                            <span className="sr-only">Open menu</span>
                            <MoreHorizontal className="h-4 w-4" />
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => setViewingJobTitle(jobTitle)}>
                            <Eye className="mr-2 h-4 w-4" />
                            {translate('jobTitles.actions.view')}
                        </DropdownMenuItem>
                        {can('job-titles.edit') && (
                            <DropdownMenuItem onClick={() => setEditingJobTitle(jobTitle)}>
                                <Edit className="mr-2 h-4 w-4" />
                                {translate('jobTitles.actions.edit')}
                            </DropdownMenuItem>
                        )}
                        <DropdownMenuSeparator />
                        {can('job-titles.delete') && (
                            <DropdownMenuItem onClick={() => setDeletingJobTitle(jobTitle)} className="text-destructive">
                                <Trash2 className="mr-2 h-4 w-4" />
                                {translate('jobTitles.actions.delete')}
                            </DropdownMenuItem>
                        )}
                    </DropdownMenuContent>
                </DropdownMenu>
            ),
        },
    ];

    return (
        <div className="bg-card">
            {jobTitles.length > 0 ? (
                <div className="rounded-md border">
                    <DataTable data={jobTitles} columns={columns} />
                </div>
            ) : (
                <Card>
                    <CardContent className="p-12 text-center">
                        <BadgeCheck className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
                        <h3 className="mb-2 text-lg font-medium">{translate('jobTitles.empty.title')}</h3>
                        <p className="text-muted-foreground">{translate('jobTitles.empty.description')}</p>
                    </CardContent>
                </Card>
            )}

            {/* Modals */}
            {editingJobTitle && (
                <EditJobTitleModal
                    jobTitle={editingJobTitle}
                    open={true}
                    onOpenChange={(open) => !open && setEditingJobTitle(null)}
                    onSuccess={() => {
                        setEditingJobTitle(null);
                    }}
                />
            )}

            {deletingJobTitle && (
                <DeleteJobTitleModal
                    jobTitle={deletingJobTitle}
                    open={true}
                    onOpenChange={(open) => !open && setDeletingJobTitle(null)}
                    onSuccess={() => {
                        setDeletingJobTitle(null);
                    }}
                />
            )}

            {viewingJobTitle && (
                <ViewJobTitleModal jobTitle={viewingJobTitle} open={true} onOpenChange={(open) => !open && setViewingJobTitle(null)} />
            )}
        </div>
    );
}
