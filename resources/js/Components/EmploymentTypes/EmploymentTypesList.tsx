import { EmploymentType } from '@/Types/employment-types';
import { Card, CardContent, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/Ui/table';
import { Badge } from '@/Components/Ui/badge';
import { Button } from '@/Components/Ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/Components/Ui/dropdown-menu';
import { MoreHorizontal, Edit, Trash2, Eye, Briefcase } from 'lucide-react';
import { useState } from 'react';
import { usePage } from '@inertiajs/react';
import EditEmploymentTypeModal from './EditEmploymentTypeModal';
import DeleteEmploymentTypeModal from './DeleteEmploymentTypeModal';
import ViewEmploymentTypeModal from './ViewEmploymentTypeModal';
import { truncateText } from '@/Lib/utils';
import usePermissions from '@/hooks/use-permissions';
import { Auth } from '@/Types';

interface EmploymentTypesListProps {
    employmentTypes: EmploymentType[];
}

export default function EmploymentTypesList({ employmentTypes }: EmploymentTypesListProps) {
    const { user } = usePage().props.auth as Auth;
    const { can } = usePermissions();
    const [editingEmploymentType, setEditingEmploymentType] = useState<EmploymentType | null>(null);
    const [deletingEmploymentType, setDeletingEmploymentType] = useState<EmploymentType | null>(null);
    const [viewingEmploymentType, setViewingEmploymentType] = useState<EmploymentType | null>(null);

    return (
        <Card>
            <CardHeader>
                <CardTitle>Employment Types</CardTitle>
            </CardHeader>
            <CardContent>
                {employmentTypes.length > 0 ? (
                    <div className="rounded-md border">
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Name</TableHead>
                                    <TableHead>Description</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Created</TableHead>
                                    <TableHead className="w-[70px]">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {employmentTypes.map((employmentType) => (
                                    <TableRow key={employmentType.id}>
                                        <TableCell>
                                            <div className="flex items-center gap-2">
                                                <div className="h-8 w-8 bg-primary/10 rounded-lg flex items-center justify-center">
                                                    <Briefcase className="h-4 w-4 text-primary" />
                                                </div>
                                                <div>
                                                    <div className="font-medium">{employmentType.name}</div>
                                                    <div className="text-sm text-muted-foreground">
                                                        {employmentType.slug}
                                                    </div>
                                                </div>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <div className="max-w-[200px] truncate">
                                                {truncateText(employmentType.description || '') || 'No description'}
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant={employmentType.is_active ? 'default' : 'secondary'}>
                                                {employmentType.is_active ? 'Active' : 'Inactive'}
                                            </Badge>
                                        </TableCell>
                                        <TableCell>
                                            {employmentType.created_at}
                                        </TableCell>
                                        <TableCell>
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
                                                        View
                                                    </DropdownMenuItem>
                                                    {can('employment-types.edit') && (
                                                        <DropdownMenuItem onClick={() => setEditingEmploymentType(employmentType)}>
                                                            <Edit className="mr-2 h-4 w-4" />
                                                            Edit
                                                        </DropdownMenuItem>
                                                    )}
                                                    <DropdownMenuSeparator />
                                                    {can('employment-types.delete') && (
                                                        <DropdownMenuItem
                                                            onClick={() => setDeletingEmploymentType(employmentType)}
                                                            className="text-destructive"
                                                        >
                                                            <Trash2 className="mr-2 h-4 w-4" />
                                                            Delete
                                                        </DropdownMenuItem>
                                                    )}
                                                </DropdownMenuContent>
                                            </DropdownMenu>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </div>
                ) : (
                    <Card>
                        <CardContent className="p-12 text-center">
                            <Briefcase className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                            <h3 className="text-lg font-medium mb-2">No Employment Types</h3>
                            <p className="text-muted-foreground">
                                Create your first employment type to get started
                            </p>
                        </CardContent>
                    </Card>
                )}
            </CardContent>

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
        </Card>
    );
}