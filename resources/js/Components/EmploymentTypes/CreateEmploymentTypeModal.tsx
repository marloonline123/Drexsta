import SharedModal from '@/Components/Shared/SharedModal';
import EmploymentTypeForm from './EmploymentTypeForm';
import useTranslation from '@/Hooks/use-translation';

interface CreateEmploymentTypeModalProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSuccess: () => void;
}

export default function CreateEmploymentTypeModal({ open, onOpenChange, onSuccess }: CreateEmploymentTypeModalProps) {
    const { translate } = useTranslation();
    return (
        <SharedModal
            open={open}
            onOpenChange={onOpenChange}
            title={translate('employment_types.modals.create.title')}
            description={translate('employment_types.modals.create.description')}
            form={
                <EmploymentTypeForm
                    action={route('dashboard.employment-types.store')}
                    method="post"
                    onSuccess={onSuccess}
                />
            }
        />
    );
}