import { Button } from '@/Components/Ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Badge } from '@/Components/Ui/badge';
import { Avatar, AvatarImage, AvatarFallback } from '@/Components/Ui/avatar';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem } from '@/Types';
import { Head, Link } from '@inertiajs/react';
import {
    Building,
    ArrowLeft,
    Edit,
    Mail,
    Users,
    Calendar,
    Trash2,
    DollarSign,
    Crown,
    User
} from 'lucide-react';
import { useState } from 'react';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/Components/Ui/table';
import DeleteDepartmentModal from '@/Components/Departments/DeleteDepartmentModal';
import { Department } from '@/Types/deparments';
import { t } from 'i18next';
import { formatCurrency } from '@/Lib/utils';
import useTranslation from '@/Hooks/use-translation';
import IsActiveTogglar from '@/Components/Shared/IsActiveTogglar';
import { StatusBadge } from '@/Components/Shared/StatusBadge';
import PageHeader from '@/Components/Shared/PageHeader';
import DepartmentOverview from '@/Components/Departments/DepartmentOverview';
import DepartmentManager from '@/Components/Departments/DepartmentManager';
import DepartmentEmployees from '@/Components/Departments/DepartmentEmployees';

interface Props {
    department: Department;
}

export default function ShowDepartment({ department }: Props) {
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    

    const { translate } = useTranslation();
    
    const breadcrumbs: BreadcrumbItem[] = [
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
    ];

    return (
        <AppLayout breadcrumbs={breadcrumbs}>
            <Head title={`${department.name} - Department Details`} />

            <div className={`p-6`}>
                {/* Header */}
                <PageHeader
                    title={
                        <h1 className="text-2xl font-bold flex items-center gap-2">
                            <Building className="h-6 w-6" />
                            {department.name}
                        </h1>
                    }
                    description={translate('departments.pages.show.description')}
                    action={
                        <div className="flex items-center gap-2">
                            <Button variant="outline" asChild>
                                <Link href={route('dashboard.departments.edit', department.slug)}>
                                    <Edit className="h-4 w-4 mr-2" />
                                    {translate('main.action_options.edit')}
                                </Link>
                            </Button>
                            <Button
                                variant="outline"
                                onClick={() => setShowDeleteModal(true)}
                                className="text-destructive hover:text-destructive"
                            >
                                <Trash2 className="h-4 w-4 mr-2" />
                                {translate('main.action_options.delete')}
                            </Button>
                        </div>
                    }
                />

                <div className="space-y-6 mt-5">
                    {/* Department Overview */}
                    <DepartmentOverview department={department} />

                    {/* Department Stats */}
                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">{translate('departments.stats.employeesCount')}</CardTitle>
                                <Users className="h-4 w-4 text-muted-foreground" />
                            </CardHeader>
                            <CardContent>
                                <div className="text-2xl font-bold">{department.employees_count + 1}</div>
                                <p className="text-xs text-muted-foreground">
                                    {translate('departments.stats.employeesCountDescription')}
                                </p>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">{translate('departments.stats.annualBudget')}</CardTitle>
                                <DollarSign className="h-4 w-4 text-muted-foreground" />
                            </CardHeader>
                            <CardContent>
                                <div className="text-2xl font-bold">{formatCurrency(department.annual_budget)}</div>
                                <p className="text-xs text-muted-foreground">
                                    {translate('departments.stats.annualBudgetDescription')}
                                </p>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">{translate('departments.stats.createdDate')}</CardTitle>
                                <Calendar className="h-4 w-4 text-muted-foreground" />
                            </CardHeader>
                            <CardContent>
                                <div className="text-2xl font-bold">
                                    {new Date(department.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                                </div>
                                <p className="text-xs text-muted-foreground">
                                    {new Date(department.created_at).getFullYear()}
                                </p>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">{translate('departments.stats.status')}</CardTitle>
                                <Crown className="h-4 w-4 text-muted-foreground" />
                            </CardHeader>
                            <CardContent>
                                <div className="text-2xl font-bold">
                                    <IsActiveTogglar
                                        route={route('dashboard.departments.toggle-status', department)}
                                        children={<StatusBadge status={!!department.is_active} />}
                                    />
                                </div>
                                <p className="text-xs text-muted-foreground">
                                    {translate('departments.stats.statusDescription')}
                                </p>
                            </CardContent>
                        </Card>
                    </div>

                    {/* Department Manager */}
                    <DepartmentManager department={department} />

                    {/* Department Employees */}
                    <DepartmentEmployees department={department} />
                </div>
            </div>

            <DeleteDepartmentModal
                department={department}
                open={showDeleteModal}
                onOpenChange={setShowDeleteModal}
                onSuccess={() => {
                    setShowDeleteModal(false);
                }}
            />
        </AppLayout>
    );
}