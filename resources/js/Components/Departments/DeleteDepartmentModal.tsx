import { DeleteModal } from '@/Components/Shared/DeleteModal';
import { router } from '@inertiajs/react';
import { Department } from '@/Types/deparments';
import useTranslation from '@/Hooks/use-translation';

interface DeleteDepartmentModalProps {
    department: Department;
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSuccess: () => void;
}

export default function DeleteDepartmentModal({ department, open, onOpenChange, onSuccess }: DeleteDepartmentModalProps) {
    const { translate } = useTranslation();

    return (
        <DeleteModal
            open={open}
            onOpenChange={onOpenChange}
            onConfirm={() => {
                router.delete(route('dashboard.departments.destroy', department.slug), {
                    onSuccess: () => {
                        onSuccess();
                    },
                });
            }}
            title={translate('main.confirmDelete') + ` "${department.name}"`}
            description={translate('main.deleteWarning')}
        />
    );
}
