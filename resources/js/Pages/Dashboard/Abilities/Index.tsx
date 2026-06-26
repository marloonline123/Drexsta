import { Head, usePage } from '@inertiajs/react';
import AppLayout from '@/Layouts/AppLayout';
import { type BreadcrumbItem, Auth } from '@/Types';
import { Button } from '@/Components/Ui/button';
import { Ability } from '@/Types/abilities';
import { PaginatedData } from '@/Types/global';
import { Plus, Zap } from 'lucide-react';
import Filter from '@/Components/Shared/Filter';
import Pagination from '@/Components/Shared/Pagination';
import { useState } from 'react';
import CreateAbilityModal from '@/Components/Abilities/CreateAbilityModal';
import AbilitiesList from '@/Components/Abilities/AbilitiesList';
import EmptyResource from '@/Components/Shared/EmptyResource';
import usePermissions from '@/hooks/use-permissions';

const breadcrumbs: BreadcrumbItem[] = [
    {
        title: 'Dashboard',
        href: route('dashboard.index'),
    },
    {
        title: 'Abilities',
        href: route('dashboard.abilities.index'),
    },
];

interface AbilitiesIndexProps {
    abilities: PaginatedData<Ability>;
}

export default function AbilitiesIndex({ abilities }: AbilitiesIndexProps) {
    const { user } = usePage().props.auth as Auth;
    const { can } = usePermissions();
    const abilitiesData = abilities?.data || [];
    const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);

    return (
        <AppLayout breadcrumbs={breadcrumbs}>
            <Head title="Abilities - Administration" />

            <div className="flex-1 space-y-6 p-6">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
                            <Zap className="h-8 w-8" />
                            Abilities
                        </h1>
                        <p className="text-muted-foreground">
                            Manage user abilities and their assignments
                        </p>
                    </div>

                    {can('abilities.create') && (
                        <Button onClick={() => setIsCreateModalOpen(true)}>
                            <Plus className="mr-2 h-4 w-4" />
                            Add Ability
                        </Button>
                    )}
                </div>

                {/* Filters and Search */}
                <Filter
                    routeName='dashboard.abilities.index'
                    fields={{
                        search: { type: 'text', placeholder: 'Search by ability label or key' },
                    }}
                />

                {/* Abilities List */}
                {abilitiesData.length === 0 ? (
                    <EmptyResource 
                        icon={Zap}
                        title="No Abilities Found"
                        description="Create a new ability to get started."
                    />
                ) : abilities ? (
                    <AbilitiesList 
                        abilities={abilitiesData} 
                    />
                ) : null}

                {/* Pagination */}
                {abilities && (
                    <Pagination
                        meta={abilities.meta}
                    />
                )}
            </div>

            {/* Create Modal */}
            <CreateAbilityModal
                open={isCreateModalOpen}
                onOpenChange={setIsCreateModalOpen}
            />
        </AppLayout>
    );
}