import { EmploymentType } from '@/Types/employment-types';
import { Card, CardContent } from '@/Components/Ui/card';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/Components/Ui/dropdown-menu';
import useTranslation from '@/Hooks/use-translation';
import { BadgeCheck, Edit, Eye, MoreHorizontal, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { DataTable } from '../Shared/DataTable';
import IsActiveTogglar from '../Shared/IsActiveTogglar';
import { StatusBadge } from '../Shared/StatusBadge';
import DeleteEmploymentTypeModal from './DeleteEmploymentTypeModal';
import EditEmploymentTypeModal from './EditEmploymentTypeModal';
import ViewEmploymentTypeModal from './ViewEmploymentTypeModal';
import usePermissions from '@/hooks/use-permissions';
import { Button } from '../Ui/button';

interface EmploymentTypesListProps {
    employmentTypes: EmploymentType[];
}

export default function EmploymentTypesList({ employmentTypes }: EmploymentTypesListProps) {
    const [editingEmploymentType, setEditingEmploymentType] = useState<EmploymentType | null>(null);
    const [deletingEmploymentType, setDeletingEmploymentType] = useState<EmploymentType | null>(null);
    const [viewingEmploymentType, setViewingEmploymentType] = useState<EmploymentType | null>(null);
    const { translate } = useTranslation();
    const { can } = usePermissions();

    const columns = [
        {
            header: translate('main.headers.title'),
            accessorKey: 'name' as keyof EmploymentType,
            cell: (employmentType: EmploymentType) => (
                <div className="flex items-center gap-2">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
                        <BadgeCheck className="h-4 w-4 text-primary" />
                    </div>
                    <div>
                        <div className="font-medium">{employmentType.name}</div>
                        {/* <div className="text-sm text-muted-foreground">{employmentType.slug}</div> */}
                    </div>
                </div>
            ),
        },
        {
            header: translate('main.headers.status'),
            cell: (employmentType: EmploymentType) => (
                <IsActiveTogglar route={route('dashboard.employment-types.toggle-status', employmentType)} children={<StatusBadge status={!!employmentType.is_active} />} />
            ),
        },
        { header: translate('main.headers.date'), accessorKey: 'created_at' as keyof EmploymentType },
        {
            header: translate('main.headers.actions'),
            className: 'text-center',
            cell: (employmentType: EmploymentType) => (
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="ghost" className="h-8 w-8 p-0">
                            <span className="sr-only">Open menu</span>
                            <MoreHorizontal className="h-4 w-4" />
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => setViewingEmploymentType(employmentType)}>
                            <Eye className="mr-2 h-4 w-4" />
                            {translate('main.action_options.view')}
                        </DropdownMenuItem>
                        {can('employment-types.edit') && (
                            <DropdownMenuItem onClick={() => setEditingEmploymentType(employmentType)}>
                                <Edit className="mr-2 h-4 w-4" />
                                {translate('main.action_options.edit')}
                            </DropdownMenuItem>
                        )}
                        <DropdownMenuSeparator />
                        {can('employment-types.delete') && (
                            <DropdownMenuItem onClick={() => setDeletingEmploymentType(employmentType)} className="text-destructive">
                                <Trash2 className="mr-2 h-4 w-4" />
                                {translate('main.action_options.delete')}
                            </DropdownMenuItem>
                        )}
                    </DropdownMenuContent>
                </DropdownMenu>
            ),
        },
    ];

    return (
        <div className="bg-card">
            {employmentTypes.length > 0 ? (
                <div className="rounded-md border">
                    <DataTable data={employmentTypes} columns={columns} />
                </div>
            ) : (
                <Card>
                    <CardContent className="p-12 text-center">
                        <BadgeCheck className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
                        <h3 className="mb-2 text-lg font-medium">{translate('employment_types.empty.title')}</h3>
                        <p className="text-muted-foreground">{translate('employment_types.empty.description')}</p>
                    </CardContent>
                </Card>
            )}

            {/* Modals */}
            {editingEmploymentType && (
                <EditEmploymentTypeModal
                    employmentType={editingEmploymentType}
                    open={true}
                    onOpenChange={(open) => !open && setEditingEmploymentType(null)}
                    onSuccess={() => {
                        setEditingEmploymentType(null);
                    }}
                />
            )}

            {deletingEmploymentType && (
                <DeleteEmploymentTypeModal
                    employmentType={deletingEmploymentType}
                    open={true}
                    onOpenChange={(open) => !open && setDeletingEmploymentType(null)}
                    onSuccess={() => {
                        setDeletingEmploymentType(null);
                    }}
                />
            )}

            {viewingEmploymentType && (
                <ViewEmploymentTypeModal
                    employmentType={viewingEmploymentType}
                    open={true}
                    onOpenChange={(open) => !open && setViewingEmploymentType(null)}
                />
            )}
        </div>
    );
}