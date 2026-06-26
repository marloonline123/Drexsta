import type { route as routeFn } from 'ziggy-js';

declare global {
    const route: typeof routeFn;
}

export interface PaginationMeta  {
        current_page: number;
        from: number | null;
        last_page: number;
        links: { url: string | null; label: string; active: boolean }[];
        path: string;
        per_page: number;
        to: number | null;
        total: number;
    };

export interface PaginationLinks {
        first: string | null;
        last: string | null;
        prev: string | null;
        next: string | null;
    };

export type PaginatedData<T> = {
    data: T[];
    links: PaginationLinks;
    meta: PaginationMeta;
};

