import { Card, CardContent } from '@/Components/Ui/card';
import AppLayout from '@/Layouts/AppLayout';
import { Auth, type BreadcrumbItem } from '@/Types';
import { Head, Link, usePage } from '@inertiajs/react';
import { buttonVariants } from '@/Components/Ui/button';
import {
    Building,
    Plus,
} from 'lucide-react';
import Pagination from '@/Components/Shared/Pagination';
import { CompaniesResponse } from '@/Types/companies';
import Filter from '@/Components/Shared/Filter';
import CompaniesGrid from '@/Components/Companies/CompaniesGrid';
import CompaniesStats from '@/Components/Companies/CompaniesStats';
import { t } from 'i18next';
import usePermissions from '@/hooks/use-permissions';

const breadcrumbs: BreadcrumbItem[] = [
    {
        title: t('nav.dashboard'),
        href: route('dashboard.index'),
    },
    {
        title: t('nav.companies'),
        href: route('dashboard.companies.index'),
    },
];

export default function CompaniesPage({ companies }: { companies: CompaniesResponse }) {
    const companiesData = companies.data || [];
    const { user } = usePage().props.auth as Auth;
    const { can } = usePermissions();

    console.log('user:', user);

    return (
        <AppLayout breadcrumbs={breadcrumbs}>
            <Head title={t('companies.title')} />

            <div className={`space-y-6 p-6`}>
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-3xl font-bold flex items-center gap-2">
                            <Building className="h-8 w-8" />
                            {t('companies.title')}
                        </h1>
                        <p className="text-muted-foreground mt-1">
                            {t('companies.description')}
                        </p>
                    </div>
                    {can('companies.create') && (
                        <Link href={route('dashboard.companies.create')} className={buttonVariants()}>
                            <Plus className="h-4 w-4 mr-2" />
                            {t('companies.addCompany')}
                        </Link>
                    )}
                </div>

                {/* Stats Cards */}
                <CompaniesStats companies={companies} />

                <Filter
                    routeName='dashboard.companies.index'
                    fields={{
                        search: { type: 'text', placeholder: 'Search by name, email...' },
                        status: {
                            type: 'select', placeholder: 'Select Status', options: [
                                { value: 'all', label: 'All' },
                                { value: 'active', label: 'Active' },
                                { value: 'inactive', label: 'Inactive' },
                            ]
                        },
                    }}
                />

                {/* Companies Grid */}
                <CompaniesGrid companies={companiesData} />

                {companiesData.length === 0 && (
                    <Card>
                        <CardContent className="p-12 text-center">
                            <Building className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                            <h3 className="text-lg font-medium mb-2">{t('companies.noCompanies')}</h3>
                            <p className="text-muted-foreground">
                                {t('companies.createFirst')}
                            </p>
                        </CardContent>
                    </Card>
                )}

                {/* Pagination */}
                <Pagination meta={companies.meta} />
            </div>
        </AppLayout>
    );
}