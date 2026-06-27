import React from 'react';
import { PaginatedData } from '@/Types/global';
import { router } from '@inertiajs/react';
import { buttonVariants } from '../Ui/button';
import { cn } from '@/Lib/utils';
import useTranslation from '@/Hooks/use-translation';

type PageLink = {
    url: string | null;
    label: string;
    active: boolean;
}

type PaginationProps<T> = {
    meta: PaginatedData<T>['meta'];
};

/**
 * Reusable pagination component that accepts the `meta` object from `PaginatedData<T>`.
 * It renders previous/next buttons and a compact list of page links.
 */
export default function Pagination<T>({ meta }: PaginationProps<T>) {
    if (!meta || (meta && meta.last_page === 1)) return null;

    const links: PageLink[] = meta.links || [];
    
    const { translate } = useTranslation();

    const renderLabel = (label: string) => {
        // Strip tags and handle common HTML entities used by Laravel pagination
        const stripped = label.replace(/<[^>]*>/g, '');
        return stripped
            .replace(/&laquo;|&lsaquo;/g, '«')
            .replace(/&raquo;|&rsaquo;/g, '»')
            .replace(/&hellip;/g, '...')
            .trim();
    };

    const navigate = (url: string | null) => {
        if (!url) return;
        router.visit(url, { preserveScroll: true });
    };    

    return (
        <nav className="flex items-center justify-between bg-card rounded-md shadow-sm mt-2 p-3">
            

            <ul className="flex items-center space-x-1 overflow-auto px-2">
                {links.map((link, idx) => {
                    const label = renderLabel(link.label);
                    const isNav = label.includes('Previous') || label.includes('Next') || label === '...';
                    const pageNumber = Number(label);
                    
                    return (
                        <li key={idx}>
                            <button
                                onClick={() => { if (link.url) navigate(link.url); }}
                                disabled={!link.url || link.active}
                                // className={`min-w-[36px] h-8 px-2 rounded-md text-sm flex items-center justify-center border ${link.active ? 'bg-primary text-white border-transparent' : 'bg-white hover:bg-gray-50'}`}
                                className={cn(buttonVariants())}
                                aria-current={link.active ? 'page' : undefined}
                            >
                                {isNav ? (label.includes('Previous') ? translate('main.previous') : label.includes('Next') ? translate('main.next') : label) : (Number.isNaN(pageNumber) ? label : pageNumber)}
                            </button>
                        </li>
                    );
                })}
            </ul>

            <div className="flex items-center space-x-2">
                <div className="text-sm text-muted-foreground">
                    {meta.current_page} - {meta.last_page}
                    {/* Page {meta.current_page} of {meta.last_page} */}
                </div>
            </div>
        </nav>
    );
}
