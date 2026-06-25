import SharedModal from '../Shared/SharedModal';
import JobTitleForm from './JobTitleForm';
import useTranslation from '@/Hooks/use-translation';

interface CreateJobTitleModalProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSuccess: () => void;
}

export default function CreateJobTitleModal({ open, onOpenChange, onSuccess }: CreateJobTitleModalProps) {
    const { translate } = useTranslation();
    return (
        <SharedModal
            title={translate('jobTitles.modals.create.title')}
            description={translate('jobTitles.modals.create.description')}
            form={
                <JobTitleForm
                    action={route('dashboard.job-titles.store')}
                    method="post"
                    onSuccess={onSuccess}
                />
            }
            open={open}
            onOpenChange={onOpenChange}
        />
        
    );
}