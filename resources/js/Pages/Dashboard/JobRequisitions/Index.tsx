import { Briefcase } from 'lucide-react';
import { t } from 'i18next'; import { toast } from 'sonner';
import { PaginatedData } from '@/Types/global';
import Filter from '@/Components/Shared/Filter';
import { Head, usePage } from '@inertiajs/react';
import { Button } from '@/Components/Ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/Ui/table';
import { Badge } from '@/Components/Ui/badge';
import { Plus, Edit, Eye, Trash2 } from 'lucide-react';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem, Auth } from '@/Types';
import { JobRequisition } from '@/Types/job-requisitions';
import { router } from '@inertiajs/core';
import usePermissions from '@/hooks/use-permissions';

const breadcrumbs: BreadcrumbItem[] = [
  {
    title: t('nav.dashboard'),
    href: route('dashboard.index'),
  },
  {
    title: t('nav.jobRequisitions'),
    href: route('dashboard.job-requisitions.index'),
  },
];

interface JobRequisitionsIndexProps {
  requisitions: PaginatedData<JobRequisition>;
}

export default function JobRequisitionsIndex({ requisitions }: JobRequisitionsIndexProps) {
  const { user } = usePage().props.auth as Auth;
  const { can } = usePermissions();
  const requisitionsData = requisitions.data;
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'draft':
        return <Badge variant="secondary">Draft</Badge>;
      case 'pending_approval':
        return <Badge className="bg-yellow-100 text-yellow-800">Pending Approval</Badge>;
      case 'approved':
        return <Badge className="bg-green-100 text-green-800">Approved</Badge>;
      case 'rejected':
        return <Badge className="bg-red-100 text-red-800">Rejected</Badge>;
      case 'closed':
        return <Badge variant="outline">Closed</Badge>;
      default:
        return <Badge variant="secondary">{status}</Badge>;
    }
  };

  const handleDelete = (requisition: JobRequisition) => {
    if (confirm('Are you sure you want to delete this job requisition?')) {
      router.delete(route('dashboard.job-requisitions.destroy', requisition.id), {
        onSuccess: () => {
          toast.success('Job requisition deleted successfully.');
        },
        onError: () => {
          toast.error('Failed to delete job requisition.');
        }
      });
    }
  };

  return (
    <AppLayout breadcrumbs={breadcrumbs}>
      <Head title="Job Requisitions - Administration" />

      <div className="flex-1 space-y-6 p-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
              <Briefcase className="h-8 w-8" />
              Job Requisitions
            </h1>
            <p className="text-muted-foreground">
              Manage job requisitions and recruitment requests
            </p>
          </div>

          {can('job-requisitions.create') && (
            <Button asChild>
              <a href={route('dashboard.job-requisitions.create')}>
                <Plus className="mr-2 h-4 w-4" />
                Add Job Requisition
              </a>
            </Button>
          )}
        </div>

        {/* Search */}
        <Filter 
          routeName='dashboard.job-requisitions.index' 
          fields={{
            search: { type: 'text', placeholder: 'Search by name' },
          }}
        />

        {/* Job Requisitions Table */}
        <Card>
          <CardHeader>
            <CardTitle>Job Requisitions</CardTitle>
            <CardDescription>
              List of all job requisitions in the system
            </CardDescription>
          </CardHeader>
          <CardContent>
            {requisitionsData.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Requisition Code</TableHead>
                    <TableHead>Job Title</TableHead>
                    <TableHead>Department</TableHead>
                    <TableHead>Positions</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {requisitionsData.map((requisition) => (
                    <TableRow key={requisition.id}>
                      <TableCell className="font-medium">{requisition.requisition_code}</TableCell>
                      <TableCell>{requisition.jobTitle?.title || 'N/A'}</TableCell>
                      <TableCell>{requisition.department?.name || 'N/A'}</TableCell>
                      <TableCell>{requisition.number_of_positions}</TableCell>
                      <TableCell>{getStatusBadge(requisition.status)}</TableCell>
                      <TableCell>{new Date(requisition.created_at).toLocaleDateString()}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button variant="outline" size="sm" asChild>
                            <a href={route('dashboard.job-requisitions.show', requisition.id)}>
                              <Eye className="h-4 w-4" />
                            </a>
                          </Button>
                          {can('job-requisitions.edit') && (
                            <Button variant="outline" size="sm" asChild>
                              <a href={route('dashboard.job-requisitions.edit', requisition.id)}>
                                <Edit className="h-4 w-4" />
                              </a>
                            </Button>
                          )}
                          {can('job-requisitions.delete') && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleDelete(requisition)}
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
                <h3 className="text-lg font-medium mb-2">No job requisitions found</h3>
                <p className="text-muted-foreground mb-4">
                  Get started by creating a new job requisition.
                </p>
                <Button asChild>
                  <a href={route('dashboard.job-requisitions.create')}>
                    <Plus className="mr-2 h-4 w-4" />
                    Add Job Requisition
                  </a>
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </AppLayout>
  );
}


