import { router } from '@inertiajs/react';
import { DeleteModal } from '@/Components/Shared/DeleteModal';
import { JobTitle } from '@/Types/job-titles';
import useTranslation from '@/Hooks/use-translation';

interface DeleteJobTitleModalProps {
    jobTitle: JobTitle;
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSuccess: () => void;
}

export default function DeleteJobTitleModal({ jobTitle, open, onOpenChange, onSuccess }: DeleteJobTitleModalProps) {
    const { translate } = useTranslation();

    return (
        <DeleteModal
            open={open}
            onOpenChange={onOpenChange}
            onConfirm={() => {
                router.delete(route('dashboard.job-titles.destroy', jobTitle.id), {
                    onSuccess: () => {
                        onSuccess();
                    },
                });
            }}
            title={translate('main.confirmDelete') + ` "${jobTitle.title}"`}
            description={translate('main.deleteWarning')}
        />
    );
}
