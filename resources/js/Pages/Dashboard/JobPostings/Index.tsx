import { Briefcase, Plus, Edit, Eye, Trash2, Play, Square } from 'lucide-react';
import { toast } from 'sonner';
import { PaginatedData } from '@/Types/global';
import Filter from '@/Components/Shared/Filter';
import { Head, Link, usePage } from '@inertiajs/react';
import { Button, buttonVariants } from '@/Components/Ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/Ui/table';
import { Badge } from '@/Components/Ui/badge';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem, Auth } from '@/Types';
import { router } from '@inertiajs/core';
import { useLanguage } from '@/Hooks/use-language';
import { usePermissions } from '@/hooks/use-permissions';
import { JobPosting } from '@/Types/job-postings';
import { cn } from '@/Lib/utils';

const breadcrumbs: BreadcrumbItem[] = [
  {
    title: 'Dashboard',
    href: route('dashboard.index'),
  },
  {
    title: 'Job Postings',
    href: route('dashboard.job-postings.index'),
  },
];

interface JobPostingsIndexProps {
  postings: PaginatedData<JobPosting>;
}

export default function JobPostingsIndex({ postings }: JobPostingsIndexProps) {
  const { t } = useLanguage();
    const { can } = usePermissions();
  const { user } = usePage().props.auth as Auth;
  const postingsData = postings.data;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'draft':
        return <Badge variant="secondary">{t('jobPostings.status.draft')}</Badge>;
      case 'open':
        return <Badge className="bg-green-100 text-green-800">{t('jobPostings.status.open')}</Badge>;
      case 'closed':
        return <Badge variant="outline">{t('jobPostings.status.closed')}</Badge>;
      default:
        return <Badge variant="secondary">{status}</Badge>;
    }
  };

  const handleDelete = (posting: JobPosting) => {
    if (confirm(t('jobPostings.confirmDelete'))) {
      router.delete(route('dashboard.job-postings.destroy', posting.slug), {
        onSuccess: () => {
          toast.success(t('jobPostings.deleteSuccess'));
        },
        onError: () => {
          toast.error(t('jobPostings.deleteError'));
        }
      });
    }
  };

  const updateStatus = (posting: JobPosting, status: 'open' | 'closed') => {
    router.patch(route('dashboard.job-postings.update-status', posting.slug),
      { status },
      {
        onSuccess: () => {
          toast.success(t('jobPostings.statusUpdateSuccess'));
        },
        onError: () => {
          toast.error(t('jobPostings.statusUpdateError'));
        }
      }
    );
  };

  return (
    <AppLayout breadcrumbs={breadcrumbs}>
      <Head title="Job Postings - Administration" />

      <div className="flex-1 space-y-6 p-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
              <Briefcase className="h-8 w-8" />
              {t('jobPostings.title')}
            </h1>
            <p className="text-muted-foreground">
              {t('jobPostings.description')}
            </p>
          </div>

          {can('job-postings.create') && (
            <Link href={route('dashboard.job-postings.create')} className={buttonVariants({ variant: 'default' })}>
              <Plus className="mr-2 h-4 w-4" />
              {t('jobPostings.addPosting')}
            </Link>
          )}
        </div>

        {/* Search */}
        <Filter
          routeName='dashboard.job-postings.index'
          fields={{
            search: { type: 'text', placeholder: t('jobPostings.searchPlaceholder') },
          }}
        />

        {/* Job Postings Table */}
        <Card>
          <CardHeader>
            <CardTitle>{t('jobPostings.listTitle')}</CardTitle>
            <CardDescription>
              {t('jobPostings.listDescription')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {postingsData.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('jobPostings.table.title')}</TableHead>
                    <TableHead>{t('jobPostings.table.requisition')}</TableHead>
                    <TableHead>{t('jobPostings.table.location')}</TableHead>
                    <TableHead>{t('jobPostings.table.status')}</TableHead>
                    <TableHead>{t('jobPostings.table.applications')}</TableHead>
                    <TableHead>{t('jobPostings.table.created')}</TableHead>
                    <TableHead className="text-right">{t('jobPostings.table.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {postingsData.map((posting) => (
                    <TableRow key={posting.slug}>
                      <TableCell className="font-medium">{posting.title}</TableCell>
                      <TableCell>
                        {posting.jobRequisition?.requisition_code || 'N/A'}
                      </TableCell>
                      <TableCell>{posting.location || (posting.is_remote ? 'Remote' : 'N/A')}</TableCell>
                      <TableCell>{getStatusBadge(posting.status)}</TableCell>
                      <TableCell>{posting.applications_count || 0}</TableCell>
                      <TableCell>{new Date(posting.created_at).toLocaleDateString()}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          {posting.status === 'draft' && can('job-postings.edit') && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => updateStatus(posting, 'open')}
                              title={t('jobPostings.openPosting')}
                            >
                              <Play className="h-4 w-4" />
                            </Button>
                          )}
                          {posting.status === 'open' && can('job-postings.edit') && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => updateStatus(posting, 'closed')}
                              title={t('jobPostings.closePosting')}
                            >
                              <Square className="h-4 w-4" />
                            </Button>
                          )}
                          <Link href={route('dashboard.job-postings.show', posting.slug)} className={cn(buttonVariants({variant: 'outline', size: 'sm'}))}>
                              <Eye className="h-4 w-4" />
                          </Link>
                          {can('job-postings.edit') && (
                            <Link href={route('dashboard.job-postings.edit', posting.slug)} className={cn(buttonVariants({variant: 'outline', size: 'sm'}))}>
                              <Edit className="h-4 w-4" />
                            </Link>
                          )}
                          {can('job-postings.delete') && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleDelete(posting)}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="text-center py-12">
                <Briefcase className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium mb-2">{t('jobPostings.noPostings')}</h3>
                <p className="text-muted-foreground mb-4">
                  {t('jobPostings.createFirst')}
                </p>
                {can('job-postings.create') && (
                    <Link href={route('dashboard.job-postings.create')} className={buttonVariants({ variant: 'default' })}>
                      <Plus className="mr-2 h-4 w-4" />
                      {t('jobPostings.addPosting')}
                    </Link>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </AppLayout>
  );
}