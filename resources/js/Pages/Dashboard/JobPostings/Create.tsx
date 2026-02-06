import React from 'react';
import { Head } from '@inertiajs/react';
import { Briefcase } from 'lucide-react';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem } from '@/Types';
import { useForm } from '@inertiajs/react';
import { JobPostingForm } from '@/Types/job-postings';
import JobPostingFormComponent from '@/Components/JobPostings/JobPostingForm';
import { JobRequisition } from '@/Types/job-requisitions';
import { t } from 'i18next';
import { EmploymentType } from '@/Types/employment-types';
import { JobTitle } from '@/Types/job-titles';

interface JobPostingsCreateProps {
  requisitions: JobRequisition[];
  employmentTypes: EmploymentType[];
  jobTitles: JobTitle[];
}

export default function JobPostingsCreate({ requisitions, employmentTypes, jobTitles }: JobPostingsCreateProps) {
  console.log('requisitions', requisitions);
  
  const { data, setData, post, processing, errors } = useForm<JobPostingForm>({
    job_requisition_id: 0,
    job_title_id: 0,
    title: '',
    description: '',
    requirements: '',
    location: '',
    min_salary: '',
    max_salary: '',
    employment_type_id: '',
    target_start_date: '',
    closing_date: '',
    status: 'draft',
    benefits: '',
    responsibilities: '',
    experience_years: '',
    education_level: '',
    is_remote: false,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    post(route('dashboard.job-postings.store'));
  };

  const breadcrumbs: BreadcrumbItem[] = [
    {
      title: t('nav.dashboard'),
      href: route('dashboard.index'),
    },
    {
      title: t('nav.jobPostings'),
      href: route('dashboard.job-postings.index'),
    },
    {
      title: t('jobPostings.createTitle'),
      href: route('dashboard.job-postings.create'),
    },
  ];

  return (
    <AppLayout breadcrumbs={breadcrumbs}>
      <Head title="Create Job Posting - Administration" />

      <div className="flex-1 space-y-6 p-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
              <Briefcase className="h-8 w-8" />
              {t('jobPostings.createTitle')}
            </h1>
            <p className="text-muted-foreground">
              {t('jobPostings.createDescription')}
            </p>
          </div>
        </div>

        <JobPostingFormComponent 
          requisitions={requisitions}
          employmentTypes={employmentTypes}
          jobTitles={jobTitles}
          data={data}
          setData={setData}
          processing={processing}
          errors={errors}
          handleSubmit={handleSubmit}
        />
      </div>
    </AppLayout>
  );
}