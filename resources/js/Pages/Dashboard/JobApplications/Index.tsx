import { Briefcase, Trash2 } from 'lucide-react';
import { t } from 'i18next';
import { toast } from 'sonner';
import { PaginatedData } from '@/Types/global';
import Filter from '@/Components/Shared/Filter';
import { Head, usePage } from '@inertiajs/react';
import { Button } from '@/Components/Ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/Ui/table';
import { Badge } from '@/Components/Ui/badge';
import { Eye, Edit } from 'lucide-react';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem, Auth, JobApplication } from '@/Types';
import { router } from '@inertiajs/core';
import usePermissions from '@/hooks/use-permissions';
import { useState } from 'react';
import { DeleteModal } from '@/Components/Shared/DeleteModal';
import UpdateStatusModal from '@/Components/JobApplications/UpdateStatusModal';

const breadcrumbs: BreadcrumbItem[] = [
  {
    title: t('nav.dashboard'),
    href: route('dashboard.index'),
  },
  {
    title: t('nav.jobApplications'),
    href: route('dashboard.job-applications.index'),
  },
];

interface JobApplicationsIndexProps {
  applications: PaginatedData<JobApplication>;
}

export default function JobApplicationsIndex({ applications }: JobApplicationsIndexProps) {
  const { user } = usePage().props.auth as Auth;
  const { can } = usePermissions();
  const applicationsData = applications.data;
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [updateModalOpen, setUpdateModalOpen] = useState(false);
  const [selectedApplication, setSelectedApplication] = useState<JobApplication | null>(null);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'applied':
        return <Badge className="bg-blue-100 text-blue-800">Applied</Badge>;
      case 'under_review':
        return <Badge className="bg-yellow-100 text-yellow-800">Under Review</Badge>;
      case 'interview':
        return <Badge className="bg-purple-100 text-purple-800">Interview</Badge>;
      case 'rejected':
        return <Badge className="bg-red-100 text-red-800">Rejected</Badge>;
      case 'hired':
        return <Badge className="bg-green-100 text-green-800">Hired</Badge>;
      default:
        return <Badge variant="secondary">{status}</Badge>;
    }
  };

  const handleDelete = (application: JobApplication) => {
    setSelectedApplication(application);
    setDeleteModalOpen(true);
  };

  const handleUpdateStatus = (application: JobApplication) => {
    setSelectedApplication(application);
    setUpdateModalOpen(true);
  };

  const confirmDelete = async () => {
    if (!selectedApplication) return;

    router.delete(route('dashboard.job-applications.destroy', selectedApplication.id), {
      onSuccess: () => {
        toast.success('Job application deleted successfully.');
        setDeleteModalOpen(false);
        setSelectedApplication(null);
      },
      onError: () => {
        toast.error('Failed to delete job application.');
      }
    });
  };

  return (
    <AppLayout breadcrumbs={breadcrumbs}>
      <Head title="Job Applications - Administration" />

      <div className="flex-1 space-y-6 p-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
              <Briefcase className="h-8 w-8" />
              Job Applications
            </h1>
            <p className="text-muted-foreground">
              Manage job applications and track candidate progress
            </p>
          </div>
        </div>

        {/* Search */}
        <Filter
          routeName='dashboard.job-applications.index'
          fields={{
            search: { type: 'text', placeholder: 'Search by name or email' },
          }}
        />

        {/* Job Applications Table */}
        <Card>
          <CardHeader>
            <CardTitle>Job Applications</CardTitle>
            <CardDescription>
              List of all job applications in the system
            </CardDescription>
          </CardHeader>
          <CardContent>
            {applicationsData.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Applicant</TableHead>
                    <TableHead>Job Position</TableHead>
                    <TableHead>Email</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Applied Date</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {applicationsData.map((application) => (
                    <TableRow key={application.id}>
                      <TableCell className="font-medium">
                        {application.first_name} {application.last_name}
                      </TableCell>
                      <TableCell>{application.jobPosting.title}</TableCell>
                      <TableCell>{application.email}</TableCell>
                      <TableCell>{getStatusBadge(application.status)}</TableCell>
                      <TableCell>{new Date(application.created_at).toLocaleDateString()}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button variant="outline" size="sm" asChild>
                            <a href={route('dashboard.job-applications.show', application.id)}>
                              <Eye className="h-4 w-4" />
                            </a>
                          </Button>
                          {can('job-applications.edit') && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleUpdateStatus(application)}
                            >
                              <Edit className="h-4 w-4" />
                            </Button>
                          )}
                          {can('job-applications.delete') && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleDelete(application)}
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
                <h3 className="text-lg font-medium mb-2">No job applications found</h3>
                <p className="text-muted-foreground mb-4">
                  Job applications will appear here once candidates apply for positions.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Update Status Modal */}
      {selectedApplication && (
        <UpdateStatusModal
          open={updateModalOpen}
          onOpenChange={setUpdateModalOpen}
          application={selectedApplication}
        />
      )}

      {/* Delete Modal */}
      <DeleteModal
        open={deleteModalOpen}
        onOpenChange={setDeleteModalOpen}
        onConfirm={confirmDelete}
        title="Delete Job Application"
        description={`Are you sure you want to delete the application from ${selectedApplication?.first_name} ${selectedApplication?.last_name}? This action cannot be undone.`}
      />
    </AppLayout>
  );
}