import { Button } from '@/Components/Ui/button';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem } from '@/Types';
import { Head, Link } from '@inertiajs/react';
import { Building, ArrowLeft } from 'lucide-react';
import DepartmentForm from '@/Components/Departments/DepartmentForm';
import { User } from '@/Types/user';
import useTranslation from '@/Hooks/use-translation';
import PageHeader from '@/Components/Shared/PageHeader';

interface Props {
    employees: User[];
}

export default function CreateDepartment({ employees }: Props) {
    const { translate } = useTranslation();

    // Dynamic breadcrumbs with translations
    const translatedBreadcrumbs: BreadcrumbItem[] = [
        {
            title: translate('nav.dashboard'),
            href: route('dashboard.index'),
        },
        {
            title: translate('departments.title'),
            href: route('dashboard.departments.index'),
        },
        {
            title: translate('departments.addTitle'),
            href: route('dashboard.departments.create'),
        },
    ];

    return (
        <AppLayout breadcrumbs={translatedBreadcrumbs}>
            <Head title="Create Department" />

            <div className={`p-6`}>
                {/* Header */}
                <PageHeader
                    title={
                        <h1 className="text-2xl font-bold flex items-center gap-2">
                            <Building className="h-6 w-6" />
                            {translate('departments.addTitle')}
                        </h1>
                    }
                    description={translate('departments.pages.create.description')}
                    action={
                        <Button variant="outline" size="icon" asChild>
                            <Link href="/dashboard/departments">
                                <ArrowLeft className="h-4 w-4" />
                            </Link>
                        </Button>
                    }
                />

                <DepartmentForm 
                    action={route('dashboard.departments.store')}
                    method="post"
                    employees={employees}
                />
            </div>
        </AppLayout>
    );
}