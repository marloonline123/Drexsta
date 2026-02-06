import { Company } from "./companies";
import { EmploymentType } from "./employment-types";

export interface JobPosting {
  id: number;
  company_id: number;
  job_requisition_id: number;
  job_title_id: number;
  job_title: string;
  title: string;
  slug: string;
  description: string | null;
  requirements: string | null;
  location: string | null;
  min_salary: number | null;
  max_salary: number | null;
  employmentType: EmploymentType;
  employment_type_id: number;
  target_start_date: string | null;
  closing_date: string | null;
  status: 'draft' | 'open' | 'closed';
  benefits: string | null;
  responsibilities: string | null;
  experience_years: number | null;
  education_level: string | null;
  is_remote: boolean;
  custom_fields: Record<string, string> | null;
  created_at: string;
  updated_at: string;
  company: Company;
  jobRequisition?: {
    id: number;
    requisition_code: string;
    jobTitle?: {
      id: number;
      title: string;
    };
    department?: {
      id: number;
      name: string;
    };
  };
  applications_count?: number;
}

export interface JobPostingForm {
  job_requisition_id: number;
  job_title_id: number;
  title: string;
  description: string;
  requirements: string;
  location: string;
  min_salary: string;
  max_salary: string;
  employment_type_id: number;
  target_start_date: string;
  closing_date: string;
  status: 'draft' | 'open' | 'closed';
  benefits: string;
  responsibilities: string;
  experience_years: number | '';
  education_level: string;
  is_remote: boolean;
}