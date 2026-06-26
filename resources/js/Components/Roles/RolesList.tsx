import { GroupedPermission, Role } from '@/Types/roles';
import { Card, CardContent, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/Ui/table';
import { Badge } from '@/Components/Ui/badge';
import { Button } from '@/Components/Ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/Components/Ui/dropdown-menu';
import { MoreHorizontal, Edit, Trash2, Eye, Crown } from 'lucide-react';
import { useState } from 'react';
import { usePage } from '@inertiajs/react';
import EditRoleModal from './EditRoleModal';
import DeleteRoleModal from './DeleteRoleModal';
import ViewRoleModal from './ViewRoleModal';
import usePermissions from '@/hooks/use-permissions';
import { Auth } from '@/Types';

interface RolesListProps {
    roles: Role[];
    groupedPermissions: Record<string, GroupedPermission[]>;
}

export default function RolesList({ roles, groupedPermissions }: RolesListProps) {
    const { user } = usePage().props.auth as Auth;
    const { can } = usePermissions();
    const [editingRole, setEditingRole] = useState<Role | null>(null);
    const [deletingRole, setDeletingRole] = useState<Role | null>(null);
    const [viewingRole, setViewingRole] = useState<Role | null>(null);

    const getRoleStatusColor = (usersCount: number) => {
        if (usersCount === 0) return 'secondary';
        if (usersCount <= 5) return 'default';
        if (usersCount <= 20) return 'secondary';
        return 'default';
    };

    return (
        <Card>
            <CardHeader>
                <CardTitle>Roles</CardTitle>
            </CardHeader>
            <CardContent>
                {roles.length > 0 ? (
                    <div className="rounded-md border">
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>{'Role Name'}</TableHead>
                                    <TableHead>{'Permissions'}</TableHead>
                                    <TableHead>{'Users'}</TableHead>
                                    <TableHead>{'Updated'}</TableHead>
                                    <TableHead className="w-[70px]">Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {roles.map((role) => (
                                    <TableRow key={role.id}>
                                        <TableCell>
                                            <div className="flex items-center gap-2">
                                                <div className="h-8 w-8 bg-primary/10 rounded-lg flex items-center justify-center">
                                                    <Crown className="h-4 w-4 text-primary" />
                                                </div>
                                                <div>
                                                    <div className="font-medium">{role.name}</div>
                                                </div>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant="outline">
                                                {role.permissions.length} permissions
                                            </Badge>
                                        </TableCell>
                                        <TableCell>
                                            <Badge variant={getRoleStatusColor(role.users_count)}>
                                                {role.users_count} users
                                            </Badge>
                                        </TableCell>
                                        <TableCell className="text-muted-foreground">
                                            {role.updated_at}
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
                                                    <DropdownMenuItem onClick={() => setViewingRole(role)}>
                                                        <Eye className="mr-2 h-4 w-4" />
                                                        View
                                                    </DropdownMenuItem>
                                                    {can('roles.edit') && (
                                                        <DropdownMenuItem onClick={() => setEditingRole(role)}>
                                                            <Edit className="mr-2 h-4 w-4" />
                                                            Edit
                                                        </DropdownMenuItem>
                                                    )}
                                                    <DropdownMenuSeparator />
                                                    {can('roles.delete') && (
                                                        <DropdownMenuItem
                                                            onClick={() => setDeletingRole(role)}
                                                            className="text-destructive"
                                                            disabled={role.users_count > 0}
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
                    <div className="p-12 text-center">
                        <Crown className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                        <h3 className="text-lg font-medium mb-2">No Roles Found</h3>
                        <p className="text-muted-foreground">
                            Create your first role to get started
                        </p>
                    </div>
                )}
            </CardContent>

            {/* Modals */}
            {editingRole && (
                <EditRoleModal
                    role={editingRole}
                    open={editingRole !== null}
                    onOpenChange={(open) => !open && setEditingRole(null)}
                    groupedPermissions={groupedPermissions}
                />
            )}

            {deletingRole && (
                <DeleteRoleModal
                    role={deletingRole}
                    open={deletingRole !== null}
                    onOpenChange={(open) => !open && setDeletingRole(null)}
                />
            )}

            {viewingRole && (
                <ViewRoleModal
                    role={viewingRole}
                    open={true}
                    onOpenChange={(open) => !open && setViewingRole(null)}
                    // groupedPermissions={groupedPermissions}
                />
            )}
        </Card>
    );
}