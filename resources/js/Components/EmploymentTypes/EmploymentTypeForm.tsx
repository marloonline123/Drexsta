import { Input } from '@/Components/Ui/input';
import { Label } from '@/Components/Ui/label';
import { Switch } from '@/Components/Ui/switch';
import { Textarea } from '@/Components/Ui/textarea';
import InputError from '@/Components/input-error';
import { EmploymentType } from '@/Types/employment-types';
import { Form, Link } from '@inertiajs/react';
import { Save } from 'lucide-react';
import { Button, buttonVariants } from '../Ui/button';
import useTranslation from '@/Hooks/use-translation';

interface EmploymentTypeFormProps {
    action: string;
    employmentType?: EmploymentType;
    method?: 'post' | 'put' | 'patch';
    onSuccess?: () => void;
}

export default function EmploymentTypeForm({ action, employmentType, method = 'post', onSuccess }: EmploymentTypeFormProps) {
    const { translate } = useTranslation();
    return (
        <Form action={action} method={method} onSuccess={onSuccess}>
            {({ processing, errors }) => (
                <div className="space-y-6">
                    <div className="space-y-2">
                        <Label htmlFor="name">
                            {translate('main.name')} <span className="text-destructive">*</span>
                        </Label>
                        <Input
                            id="name"
                            name="name"
                            placeholder={translate('employment_types.form.placeholder.title')}
                            required
                            autoFocus
                            defaultValue={employmentType?.name || ''}
                        />
                        <InputError message={errors.name} />
                    </div>

                    {/* Description */}
                    <div className="space-y-2">
                        <Label htmlFor="description">{translate('main.description')}</Label>
                        <Textarea
                            id="description"
                            name="description"
                            placeholder={translate('employment_types.form.placeholder.description')}
                            rows={4}
                            defaultValue={employmentType?.description || ''}
                        />
                        <InputError message={errors.description} />
                    </div>
                    <div className="flex items-center justify-between">
                        <div className="space-y-0.5">
                            <Label>{translate('main.status')}</Label>
                            <p className="text-sm text-muted-foreground">{translate('employment_types.form.descriptions.status')}</p>
                        </div>
                        <Switch name="is_active" defaultChecked={employmentType?.is_active ?? true} />
                    </div>

                    {/* Form Actions */}
                    <div className="flex items-center justify-end gap-4 border-t pt-6">
                        <Link href="/dashboard/employment-types" className={buttonVariants({ variant: 'outline' })}>
                            {translate('main.cancel')}
                        </Link>
                        <Button type="submit" disabled={processing}>
                            <Save className="mr-2 h-4 w-4" />
                            {processing ? translate('main.loading') : employmentType ? translate('main.update') : translate('main.create')}
                        </Button>
                    </div>
                </div>
            )}
        </Form>
    );
}