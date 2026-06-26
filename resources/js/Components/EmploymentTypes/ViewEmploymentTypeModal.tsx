import SharedModal from '@/Components/Shared/SharedModal';
import { EmploymentType } from '@/Types/employment-types';
import { Badge } from '@/Components/Ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Label } from '@/Components/Ui/label';
import { format } from 'date-fns';
import useTranslation from '@/Hooks/use-translation';

interface ViewEmploymentTypeModalProps {
    employmentType: EmploymentType;
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

export default function ViewEmploymentTypeModal({ employmentType, open, onOpenChange }: ViewEmploymentTypeModalProps) {
    const { translate } = useTranslation();
    return (
        <SharedModal
            open={open}
            onOpenChange={onOpenChange}
            title={translate('employment_types.modals.view.title')}
            description={''}
            form={
                <Card className="border-0 shadow-none">
                    <CardHeader className="p-0 mb-4">
                        <CardTitle className="flex items-center justify-between">
                            <span>{employmentType.name}</span>
                            <Badge variant={employmentType.is_active ? 'default' : 'secondary'}>
                                {employmentType.is_active ? translate('main.active') : translate('main.inactive')}
                            </Badge>
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label>{translate('employment_types.fields.slug')}</Label>
                                <p className="text-sm">{employmentType.slug}</p>
                            </div>
                            
                            <div className="space-y-2">
                                <Label>{translate('employment_types.fields.createdAt')}</Label>
                                <p className="text-sm">
                                    {employmentType.created_at ? format(new Date(employmentType.created_at), 'PPP') : 'N/A'}
                                </p>
                            </div>
                            
                            <div className="space-y-2 md:col-span-2">
                                <Label>{translate('employment_types.fields.description')}</Label>
                                <p className="text-sm">
                                    {employmentType.description || translate('employment_types.empty.description')}
                                </p>
                            </div>
                            
                            {employmentType.company && (
                                <div className="space-y-2 md:col-span-2">
                                    <Label>{translate('employment_types.fields.company')}</Label>
                                    <p className="text-sm">{employmentType.company.name}</p>
                                </div>
                            )}
                        </div>
                    </CardContent>
                </Card>
            }
        />
    );
}