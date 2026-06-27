import { Card, CardContent } from '@/Components/Ui/card';
import useTranslation from '@/Hooks/use-translation';
import { Department } from '@/Types/deparments';
import { BadgeCheck, Edit, Eye, MoreHorizontal, Trash2, Users, DollarSign, Crown, Calendar } from 'lucide-react';
import { useState } from 'react';
import { DataTable } from '../Shared/DataTable';
import DeleteDepartmentModal from './DeleteDepartmentModal';
import { formatCurrency } from '@/Lib/utils';
import DepartmentTableActionsDropdown from './DepartmentTableActionsDropdown';

interface DepartmentsListProps {
    departments: Department[];
}

export default function DepartmentsList({ departments }: DepartmentsListProps) {
    const [deletingDepartment, setDeletingDepartment] = useState<Department | null>(null);
    const { translate } = useTranslation();

    const columns = [
        {
            header: translate('main.headers.name'),
            accessorKey: 'name' as keyof Department,
            cell: (department: Department) => (
                <div className="flex items-center gap-2">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
                        <BadgeCheck className="h-4 w-4 text-primary" />
                    </div>
                    <div>
                        <div className="font-medium">{department.name}</div>
                        <div className="text-sm text-muted-foreground line-clamp-1">{department.description}</div>
                    </div>
                </div>
            ),
        },
        {
            header: translate('main.headers.manager'),
            cell: (department: Department) => (
                <div className="flex items-center gap-2">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
                        <Crown className="h-4 w-4 text-primary" />
                    </div>
                    <div>
                        <div className="font-medium">{department.manager?.name || 'N/A'}</div>
                        <div className="text-sm text-muted-foreground">{department.manager?.email || 'N/A'}</div>
                    </div>
                </div>
            ),
        },
        {
            header: translate('main.headers.employees'),
            cell: (department: Department) => (
                <div className="flex items-center gap-1">
                    <Users className="h-4 w-4 text-muted-foreground" />
                    {department.employees_count}
                </div>
            ),
        },
        {
            header: translate('main.headers.budget'),
            cell: (department: Department) => (
                <span className="font-medium">
                    {formatCurrency(department.annual_budget)}
                </span>
            ),
        },
        {
            header: translate('main.headers.status'),
            cell: (department: Department) => (
                <div className="flex items-center gap-2">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
                        <DollarSign className="h-4 w-4 text-primary" />
                    </div>
                    <div>
                        <div className="font-medium">{department.is_active ? 'Active' : 'Inactive'}</div>
                    </div>
                </div>
            ),
        },
        {
            header: translate('main.headers.date'),
            accessorKey: 'created_at' as keyof Department,
            cell: (department: Department) => (
                <div className="font-medium">
                    {new Date(department.created_at).toLocaleDateString()}
                </div>
            ),
        },
        {
            header: translate('main.headers.actions'),
            className: 'text-center',
            cell: (department: Department) => (
                <DepartmentTableActionsDropdown 
                    department={department}
                    onDelete={() => setDeletingDepartment(department)}
                />
            ),
        },
    ];

    return (
        <div className="bg-card">
            {departments.length > 0 ? (
                <div className="rounded-md border">
                    <DataTable data={departments} columns={columns} />
                </div>
            ) : (
                <Card>
                    <CardContent className="p-12 text-center">
                        <BadgeCheck className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
                        <h3 className="mb-2 text-lg font-medium">{translate('departments.empty.title')}</h3>
                        <p className="text-muted-foreground">{translate('departments.empty.description')}</p>
                    </CardContent>
                </Card>
            )}

            {deletingDepartment && (
                <DeleteDepartmentModal
                    department={deletingDepartment}
                    open={true}
                    onOpenChange={(open) => !open && setDeletingDepartment(null)}
                    onSuccess={() => {
                        setDeletingDepartment(null);
                    }}
                />
            )}
        </div>
    );
}
