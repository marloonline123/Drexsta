import { Head, usePage } from '@inertiajs/react';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem, Auth } from '@/Types';
import { Button } from '@/Components/Ui/button';
import { Role } from '@/Types/roles';
import { PaginatedData } from '@/Types/global';
import RolesStats from '@/Components/Roles/RolesStats';
import RolesList from '@/Components/Roles/RolesList';
import CreateRoleModal from '@/Components/Roles/CreateRoleModal';
import { Plus, Crown } from 'lucide-react';
import Filter from '@/Components/Shared/Filter';
import Pagination from '@/Components/Shared/Pagination';
import { useState, useEffect } from 'react';
import EmptyResource from '@/Components/Shared/EmptyResource';
import usePermissions from '@/hooks/use-permissions';

const breadcrumbs: BreadcrumbItem[] = [
    {
        title: 'Dashboard',
        href: route('dashboard.index'),
    },
    {
        title: 'Roles',
        href: route('dashboard.roles.index'),
    },
];

interface RolesIndexProps {
    roles: PaginatedData<Role>;
    permissions: Record<string, any[]>;
}

export default function RolesIndex({ roles, permissions }: RolesIndexProps) {
    const { user } = usePage().props.auth as Auth;
    const { can } = usePermissions();
    const rolesData = roles?.data || [];
    const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
    const [groupedPermissions, setGroupedPermissions] = useState<Record<string, any[]>>(permissions || {});

    // Fetch permissions on component mount
    useEffect(() => {
        fetchPermissions();
    }, []);

    const fetchPermissions = async () => {
        try {
            const response = await fetch(route('dashboard.roles.permissions'));
            const data = await response.json();
            setGroupedPermissions(data.permissions);
        } catch (error) {
            console.error('Error fetching permissions:', error);
        }
    };

    return (
        <AppLayout breadcrumbs={breadcrumbs}>
            <Head title="Roles - Administration" />

            <div className="flex-1 space-y-6 p-6">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
                            <Crown className="h-8 w-8" />
                            Roles
                        </h1>
                        <p className="text-muted-foreground">
                            Manage roles and their assigned permissions
                        </p>
                    </div>

                    {can('roles.create') && (
                        <Button onClick={() => setIsCreateModalOpen(true)}>
                            <Plus className="mr-2 h-4 w-4" />
                            Add Role
                        </Button>
                    )}
                </div>

                {/* Overview Cards */}
                {roles && (
                    <RolesStats roles={roles} groupedPermissions={groupedPermissions} />
                )}

                {/* Filters and Search */}
                <Filter
                    routeName='dashboard.roles.index'
                    fields={{
                        search: { type: 'text', placeholder: 'Search by role name' },
                    }}
                />

                {/* Roles List */}
                {rolesData.length === 0 ? (
                    <EmptyResource 
                        icon={Crown}
                        title="No Roles Found"
                        description="Create a new role to get started."
                    />
                ) : roles ? (
                    <RolesList 
                        roles={rolesData} 
                        groupedPermissions={groupedPermissions}
                    />
                ) : null}

                {/* Pagination */}
                <Pagination
                    meta={roles.meta}
                />
            </div>

            {/* Create Modal */}
            <CreateRoleModal
                open={isCreateModalOpen}
                onOpenChange={setIsCreateModalOpen}
                groupedPermissions={groupedPermissions}
            />
        </AppLayout>
    );
}