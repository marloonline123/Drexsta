import { Badge } from '@/Components/Ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/Components/Ui/avatar';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/Components/Ui/dropdown-menu';
import { MoreHorizontal, Edit, Users, Eye, Trash2 } from 'lucide-react';
import { formatCurrency } from '@/Lib/utils';
import { Link, usePage } from '@inertiajs/react';
import { Button } from '../Ui/button';
import {
    TableCell,
    TableRow,
} from '@/Components/Ui/table';
import { Department } from '@/Types/deparments';
import DeleteDepartmentModal from './DeleteDepartmentModal';
import { useState } from 'react';
import usePermissions from '@/hooks/use-permissions';
import { Auth } from '@/Types';

export default function DepartmentTableRow({ department }: { department: Department }) {
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const { user } = usePage().props.auth as Auth;
    const { can } = usePermissions();
    const { can } = usePermissions();

    return (
        <TableRow key={department.id}>
            <TableCell>
                <div>
                    <div className="font-medium">{department.name}</div>
                    <div className="text-sm text-muted-foreground line-clamp-1">
                        {department.description}
                    </div>
                </div>
            </TableCell>
            <TableCell>
                <div className="flex items-center gap-2">
                    <Avatar className="h-8 w-8">
                        <AvatarImage src={department.manager.profile_photo_url} />
                        <AvatarFallback>
                            {department.manager.name.split(' ').map(n => n[0]).join('')}
                        </AvatarFallback>
                    </Avatar>
                    <div>
                        <div className="font-medium">{department.manager.name}</div>
                        <div className="text-sm text-muted-foreground">
                            {department.manager.email}
                        </div>
                    </div>
                </div>
            </TableCell>
            <TableCell>
                <div className="flex items-center gap-1">
                    <Users className="h-4 w-4 text-muted-foreground" />
                    {department.employees_count}
                </div>
            </TableCell>
            <TableCell>
                <span className="font-medium">
                    {formatCurrency(department.annual_budget)}
                </span>
            </TableCell>
            <TableCell>
                <Badge variant={department.is_active ? 'default' : 'secondary'}>
                    {department.is_active ? 'active' : 'inactive'}
                </Badge>
            </TableCell>
            <TableCell>
                {new Date(department.created_at).toLocaleDateString()}
            </TableCell>
            <TableCell>
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="ghost" className="h-8 w-8 p-0">
                            <MoreHorizontal className="h-4 w-4" />
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                        <DropdownMenuLabel>Actions</DropdownMenuLabel>
                        <Link href={route('dashboard.departments.show', department.slug)}>
                            <DropdownMenuItem>
                                <Eye className="mr-2 h-4 w-4" />
                                View
                            </DropdownMenuItem>
                        </Link>
                        {can('departments.edit') && (
                            <Link href={route('dashboard.departments.edit', department.slug)}>
                                <DropdownMenuItem>
                                    <Edit className="mr-2 h-4 w-4" />
                                    Edit
                                </DropdownMenuItem>
                            </Link>
                        )}
                        <DropdownMenuSeparator />
                        {can('departments.delete') && (
                            <DropdownMenuItem
                                onClick={() => setShowDeleteModal(true)}
                                className="text-destructive"
                            >
                                <Trash2 className="mr-2 h-4 w-4" />
                                Delete
                            </DropdownMenuItem>
                        )}
                        {/* <DeleteDepartmentModal department={department} /> */}
                    </DropdownMenuContent>
                </DropdownMenu>
                <DeleteDepartmentModal
                    department={department}
                    showDeleteModal={showDeleteModal}
                    setShowDeleteModal={setShowDeleteModal}
                />
            </TableCell>
        </TableRow>
    )
}
