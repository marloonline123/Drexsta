import { EmploymentType } from '@/Types/employment-types';
import { DeleteModal } from '@/Components/Shared/DeleteModal';
import { router } from '@inertiajs/react';
import { useState } from 'react';
import { toast } from 'sonner';
import useTranslation from '@/Hooks/use-translation';

interface DeleteEmploymentTypeModalProps {
    employmentType: EmploymentType;
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSuccess: () => void;
}

export default function DeleteEmploymentTypeModal({ 
    employmentType, 
    open, 
    onOpenChange, 
    onSuccess 
}: DeleteEmploymentTypeModalProps) {
    const [isDeleting, setIsDeleting] = useState(false);
    const { translate } = useTranslation();

    const handleDelete = async () => {
        if (isDeleting) return;

        setIsDeleting(true);
        try {
            router.delete(route('dashboard.employment-types.destroy', employmentType.id), {
                onSuccess: () => {
                    toast.success(translate('flash.deleteSuccess'));
                    onSuccess();
                },
                onError: () => {
                    toast.error(translate('flash.deleteError'));
                },
                onFinish: () => {
                    setIsDeleting(false);
                    onOpenChange(false);
                }
            });
        } catch {
            toast.error(translate('flash.deleteError'));
            setIsDeleting(false);
            onOpenChange(false);
        }
    };

    return (
        <DeleteModal
            open={open}
            onOpenChange={onOpenChange}
            onConfirm={handleDelete}
            loading={isDeleting}
            title={translate('main.confirmDelete') + ` "${employmentType.name}"`}
            description={translate('main.deleteWarning')}
            actionButtonText={translate('main.delete')}
        >
            <div className="space-y-4">
                <div className="p-4 bg-muted rounded-lg">
                    <h4 className="font-medium">{employmentType.name}</h4>
                    <p className="text-sm text-muted-foreground">
                        {employmentType.description || translate('employment_types.empty.description')}
                    </p>
                </div>

                <div className="text-sm text-destructive bg-destructive/10 p-3 rounded-lg">
                    <p className="font-medium">{translate('main.warning')}:</p>
                    <p>{translate('main.deleteWarning')}</p>
                </div>
            </div>
        </DeleteModal>
    );
}