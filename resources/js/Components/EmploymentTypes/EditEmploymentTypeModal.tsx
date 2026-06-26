import SharedModal from '@/Components/Shared/SharedModal';
import EmploymentTypeForm from './EmploymentTypeForm';
import useTranslation from '@/Hooks/use-translation';

interface EditEmploymentTypeModalProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    employmentType: any;
    onSuccess: () => void;
}

export default function EditEmploymentTypeModal({ open, onOpenChange, employmentType, onSuccess }: EditEmploymentTypeModalProps) {
    const { translate } = useTranslation();
    return (
        <SharedModal
            open={open}
            onOpenChange={onOpenChange}
            title={translate('employment_types.modals.edit.title')}
            description={translate('employment_types.modals.edit.description')}
            form={
                <EmploymentTypeForm
                    action={route('dashboard.employment-types.update', employmentType.id)}
                    method="put"
                    employmentType={employmentType}
                    onSuccess={onSuccess}
                />
            }
        />
    );
}