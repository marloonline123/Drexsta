import SharedModal from '@/Components/Shared/SharedModal';
import { JobTitle } from '@/Types/job-titles';
import { Badge } from '@/Components/Ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Label } from '@/Components/Ui/label';
import { format } from 'date-fns';
import useTranslation from '@/Hooks/use-translation';

interface ViewJobTitleModalProps {
    jobTitle: JobTitle;
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

export default function ViewJobTitleModal({ jobTitle, open, onOpenChange }: ViewJobTitleModalProps) {
    const { translate } = useTranslation();
    return (
        <SharedModal
            open={open}
            onOpenChange={onOpenChange}
            title={translate('job_titles.modals.view.title')}
            description={''}
            children={
                <Card className="border-0 shadow-none">
                    <CardHeader className="p-0 mb-4">
                        <CardTitle className="flex items-center justify-between">
                            <span>{jobTitle.title}</span>
                            <Badge variant={jobTitle.is_active ? 'default' : 'secondary'}>
                                {jobTitle.is_active ? translate('main.active') : translate('main.inactive')}
                            </Badge>
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label>{translate('job_titles.fields.slug')}</Label>
                                <p className="text-sm">{jobTitle.slug}</p>
                            </div>
                            
                            <div className="space-y-2">
                                <Label>{translate('job_titles.fields.createdAt')}</Label>
                                <p className="text-sm">
                                    {jobTitle.created_at ? format(new Date(jobTitle.created_at), 'PPP') : 'N/A'}
                                </p>
                            </div>
                            
                            <div className="space-y-2 md:col-span-2">
                                <Label>{translate('job_titles.fields.description')}</Label>
                                <p className="text-sm">
                                    {jobTitle.description || translate('jobTitles.empty.description')}
                                </p>
                            </div>
                            
                            {jobTitle.company && (
                                <div className="space-y-2 md:col-span-2">
                                    <Label>{translate('job_titles.fields.company')}</Label>
                                    <p className="text-sm">{jobTitle.company.name}</p>
                                </div>
                            )}
                        </div>
                    </CardContent>
                </Card>
            }
        />
    );
}