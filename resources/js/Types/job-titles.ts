import { Company } from './companies';

export type JobTitle = {
    id: number;
    title: string;
    slug: string;
    description: string;
    is_active: boolean;
    company?: Company;
    created_at: string;
    updated_at: string;
};

export type JobTitleFormData = {
    title: string;
    description?: string;
    is_active?: boolean;
};