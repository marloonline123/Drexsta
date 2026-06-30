import useTranslation from '@/Hooks/use-translation';
import { JobTitle } from '@/Types/job-titles';
import JobTitleForm from './JobTitleForm';
import SharedModal from '../Shared/SharedModal';

interface EditJobTitleModalProps {
    jobTitle: JobTitle;
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSuccess: () => void;
}

export default function EditJobTitleModal({ jobTitle, open, onOpenChange, onSuccess }: EditJobTitleModalProps) {
    const { translate } = useTranslation();
    return (
        <SharedModal
            title={translate('job_titles.modals.edit.title')}
            description={translate('job_titles.modals.edit.description')}
            children={
                <JobTitleForm
                    jobTitle={jobTitle}
                    action={route('dashboard.job-titles.update', jobTitle)}
                    method="post"
                    onSuccess={onSuccess}
                />
            }
            open={open}
            onOpenChange={onOpenChange}
        />
    );
}
