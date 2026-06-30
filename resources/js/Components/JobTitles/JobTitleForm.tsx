import { Input } from '@/Components/Ui/input';
import { Label } from '@/Components/Ui/label';
import { Switch } from '@/Components/Ui/switch';
import { Textarea } from '@/Components/Ui/textarea';
import InputError from '@/Components/input-error';
import { JobTitle } from '@/Types/job-titles';
import { Form, Link } from '@inertiajs/react';
import { Save } from 'lucide-react';
import { Button, buttonVariants } from '../Ui/button';
import useTranslation from '@/Hooks/use-translation';

interface JobTitleFormProps {
    action: string;
    jobTitle?: JobTitle;
    method?: 'post' | 'put' | 'patch';
    onSuccess?: () => void;
}

export default function JobTitleForm({ action, jobTitle, method = 'post', onSuccess }: JobTitleFormProps) {
    const { translate } = useTranslation();
    return (
        <Form action={action} method={method} onSuccess={onSuccess}>
            {({ processing, errors }) => (
                <div className="space-y-6">
                    <div className="space-y-2">
                        <Label htmlFor="title">
                            {translate('job_titles.form.labels.title')} <span className="text-destructive">*</span>
                        </Label>
                        <Input id="title" name="title" placeholder={translate('job_titles.form.placeholder.title')} required autoFocus defaultValue={jobTitle?.title || ''} />
                        <InputError message={errors.title} />
                    </div>

                    {/* Description */}
                    <div className="space-y-2">
                        <Label htmlFor="description">{translate('job_titles.form.labels.description')}</Label>
                        <Textarea
                            id="description"
                            name="description"
                            placeholder={translate('job_titles.form.placeholder.description')}
                            rows={4}
                            defaultValue={jobTitle?.description || ''}
                        />
                        <InputError message={errors.description} />
                    </div>
                    <div className="flex items-center justify-between">
                        <div className="space-y-0.5">
                            <Label>{translate('job_titles.form.labels.status')}</Label>
                            <p className="text-sm text-muted-foreground">{translate('job_titles.form.descriptions.status')}</p>
                        </div>
                        <Switch name="is_active" defaultChecked={jobTitle?.is_active ?? true} />
                    </div>

                    {/* Form Actions */}
                    <div className="flex items-center justify-end gap-4 border-t pt-6">
                        <Link href={route('dashboard.job-titles.index')} className={buttonVariants({ variant: 'outline' })}>
                            {translate('job_titles.form.actions.cancel')}
                        </Link>
                        <Button type="submit" disabled={processing}>
                            <Save className="mr-2 h-4 w-4" />
                            {processing ? translate('job_titles.form.actions.saving') : jobTitle ? translate('job_titles.form.actions.update') : translate('job_titles.form.actions.create')}
                        </Button>
                    </div>
                </div>
            )}
        </Form>
    );
}
