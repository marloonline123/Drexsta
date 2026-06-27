import { Button } from '@/Components/Ui/button';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem } from '@/Types';
import { Head, Link } from '@inertiajs/react';
import { Building, ArrowLeft } from 'lucide-react';
import DepartmentForm from '@/Components/Departments/DepartmentForm';
import { Department } from '@/Types/deparments';
import { t } from 'i18next';
import { User } from '@/Types/user';
import useTranslation from '@/Hooks/use-translation';
import PageHeader from '@/Components/Shared/PageHeader';

interface Props {
    department: Department;
    employees: User[];
}

export default function EditDepartment({ department, employees }: Props) {
    console.log('Employees:', employees);
    console.log('Department:', department);
    

    const { translate } = useTranslation();
    
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
            title: department.name,
            href: route('dashboard.departments.show', department.slug),
        },
        {
            title: translate('main.action_options.edit'),
            href: route('dashboard.departments.edit', department.slug),
        },
    ];

    return (
        <AppLayout breadcrumbs={translatedBreadcrumbs}>
            <Head title={`Edit ${department.name}`} />

            <div className={`p-6`}>
                {/* Header */}
                <PageHeader
                    title={
                        <h1 className="text-2xl font-bold flex items-center gap-2">
                            <Building className="h-6 w-6" />
                            {translate('departments.pages.edit.title')}
                        </h1>
                    }
                    description={translate('departments.pages.edit.description')}
                    action={
                        <Button variant="outline" size="icon" asChild>
                            <Link href={route('dashboard.departments.index')}>
                                <ArrowLeft className="h-4 w-4" />
                            </Link>
                        </Button>
                    }
                />

                <DepartmentForm 
                    action={route('dashboard.departments.update', department.slug)}
                    method="put"
                    department={department}
                    employees={employees}
                />
            </div>
        </AppLayout>
    );
}