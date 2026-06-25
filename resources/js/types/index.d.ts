import { LucideIcon } from 'lucide-react';
import type { Config } from 'ziggy-js';
import { User } from './user';

export type { Employee } from './employees';
export type { JobApplication, JobApplicationForm } from './job-applications';

export interface Auth {
    user: User;
}

export interface BreadcrumbItem {
    title: string;
    href: string;
}

export interface NavGroup {
    title: string;
    items: NavItem[];
}

export interface NavItem {
    title: string;
    href: string;
    icon?: LucideIcon | null;
    isActive?: boolean;
    permission: string | null;
}

export interface NavItemData {
    categoryName: string;
    categoryIcon: LucideIcon | null;
    items: NavItem[];
}

export type NavItemsData = NavItemData[];

export interface PageProps {
    name: string;
    quote: { message: string; author: string };
    auth: Auth;
    ziggy: Config & { location: string };
    sidebarOpen: boolean;
    translations: Record<string, string>;
    flash: {
        success?: string;
        error?: string;
    }
    [key: string]: unknown;
}