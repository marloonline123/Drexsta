import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Button, buttonVariants } from '@/Components/Ui/button';
import { Label } from '@/Components/Ui/label';
import { Input } from '@/Components/Ui/input';
import { Textarea } from '@/Components/Ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/Components/Ui/select';
import { Switch } from '@/Components/Ui/switch';
import { Save, ArrowLeft } from 'lucide-react';
import { Link } from '@inertiajs/react';
import { JobPostingForm as JobPostingFormType } from '@/Types/job-postings';
import { InputError } from '@/Components/Ui/InputError';
import { useLanguage } from '@/Hooks/use-language';
import { JobRequisition } from '@/Types/job-requisitions';
import { EmploymentType } from '@/Types/employment-types';
import { JobTitle } from '@/Types/job-titles';

interface JobPostingFormProps {
    requisitions: JobRequisition[];
    employmentTypes: EmploymentType[];
    jobTitles: JobTitle[];
    handleSubmit: (e: React.FormEvent) => void;
    data: JobPostingFormType;
    setData: (key: keyof JobPostingFormType, value: string | number | boolean) => void;
    processing: boolean;
    errors: Record<string, string>;
}

export default function JobPostingForm({ requisitions, employmentTypes, jobTitles, handleSubmit, data, setData, processing, errors }: JobPostingFormProps) {
    const { t } = useLanguage();

    return (
        <form onSubmit={handleSubmit}>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Main Information */}
                <div className="lg:col-span-2 space-y-6">
                    <Card>
                        <CardHeader>
                            <CardTitle>{t('jobPostings.form.jobDetails')}</CardTitle>
                            <CardDescription>
                                {t('jobPostings.form.jobDetailsDescription')}
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="space-y-2">
                                <Label htmlFor="job_requisition_id">
                                    {t('jobPostings.form.requisition')} <span className="text-destructive">*</span>
                                </Label>
                                <Select
                                    value={data.job_requisition_id.toString()}
                                    onValueChange={(value) => setData('job_requisition_id', parseInt(value))}
                                >
                                    <SelectTrigger>
                                        <SelectValue>{t('jobPostings.form.selectRequisition')}</SelectValue>
                                    </SelectTrigger>
                                    <SelectContent>
                                        {requisitions.map((requisition) => (
                                            <SelectItem key={requisition.id} value={requisition.id.toString()}>
                                                {requisition.requisition_code}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                                <InputError message={errors?.job_requisition_id} />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="title">
                                    {t('jobPostings.form.title')} <span className="text-destructive">*</span>
                                </Label>
                                <Input
                                    id="title"
                                    value={data.title}
                                    onChange={(e) => setData('title', e.target.value)}
                                    placeholder={t('jobPostings.form.titlePlaceholder')}
                                />
                                <InputError message={errors?.title} />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="description">{t('jobPostings.form.description')}</Label>
                                <Textarea
                                    id="description"
                                    rows={6}
                                    value={data.description || ''}
                                    onChange={(e) => setData('description', e.target.value)}
                                    placeholder={t('jobPostings.form.descriptionPlaceholder')}
                                />
                                <InputError message={errors?.description} />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="requirements">{t('jobPostings.form.requirements')}</Label>
                                <Textarea
                                    id="requirements"
                                    rows={6}
                                    value={data.requirements || ''}
                                    onChange={(e) => setData('requirements', e.target.value)}
                                    placeholder={t('jobPostings.form.requirementsPlaceholder')}
                                />
                                <InputError message={errors?.requirements} />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="responsibilities">{t('jobPostings.form.responsibilities')}</Label>
                                <Textarea
                                    id="responsibilities"
                                    rows={4}
                                    value={data.responsibilities || ''}
                                    onChange={(e) => setData('responsibilities', e.target.value)}
                                    placeholder={t('jobPostings.form.responsibilitiesPlaceholder')}
                                />
                                <InputError message={errors?.responsibilities} />
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle>{t('jobPostings.form.additionalInfo')}</CardTitle>
                            <CardDescription>
                                {t('jobPostings.form.additionalInfoDescription')}
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="space-y-2">
                                <Label htmlFor="benefits">{t('jobPostings.form.benefits')}</Label>
                                <Textarea
                                    id="benefits"
                                    rows={4}
                                    value={data.benefits || ''}
                                    onChange={(e) => setData('benefits', e.target.value)}
                                    placeholder={t('jobPostings.form.benefitsPlaceholder')}
                                />
                                <InputError message={errors?.benefits} />
                            </div>
                        </CardContent>
                    </Card>
                </div>

                {/* Sidebar */}
                <div className="space-y-6">
                    <Card>
                        <CardHeader>
                            <CardTitle>{t('jobPostings.form.employmentDetails')}</CardTitle>
                            <CardDescription>
                                {t('jobPostings.form.employmentDetailsDescription')}
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="space-y-2">
                                <Label htmlFor="job_title_id">{t('jobPostings.form.jobTitle')}</Label>
                                <Select
                                    value={data.job_title_id.toString()}
                                    onValueChange={(value) => setData('job_title_id', value)}
                                >
                                    <SelectTrigger>
                                        <SelectValue>{t('jobPostings.form.selectJobTitle')}</SelectValue>
                                    </SelectTrigger>
                                    <SelectContent>
                                        {jobTitles.length > 0 ? jobTitles.map((jobTitle) => (
                                            <SelectItem
                                                key={jobTitle.id}
                                                value={jobTitle.id.toString()}
                                            >
                                                {jobTitle.title}
                                            </SelectItem>
                                        )) : (
                                            <div className='p-2 text-sm text-muted-foreground text-center'>{t('jobPostings.form.noJobTitle')}</div>
                                        )}
                                    </SelectContent>
                                </Select>
                                <InputError message={errors?.job_title_id} />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="employment_type_id">{t('jobPostings.form.employmentType')}</Label>
                                <Select
                                    value={data.employment_type_id.toString()}
                                    onValueChange={(value) => setData('employment_type_id', value)}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder={t('jobPostings.form.selectEmploymentType')} />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {employmentTypes.map((employmentType) => (
                                            <SelectItem
                                                key={employmentType.id}
                                                value={employmentType.id.toString()}
                                            >
                                                {employmentType.name}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                                <InputError message={errors?.employment_type_id} />
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <Label htmlFor="min_salary">{t('jobPostings.form.minSalary')}</Label>
                                    <Input
                                        id="min_salary"
                                        type="number"
                                        step="0.01"
                                        value={data.min_salary || ''}
                                        onChange={(e) => setData('min_salary', e.target.value)}
                                        placeholder="0.00"
                                    />
                                    <InputError message={errors?.min_salary} />
                                </div>

                                <div className="space-y-2">
                                    <Label htmlFor="max_salary">{t('jobPostings.form.maxSalary')}</Label>
                                    <Input
                                        id="max_salary"
                                        type="number"
                                        step="0.01"
                                        value={data.max_salary || ''}
                                        onChange={(e) => setData('max_salary', e.target.value)}
                                        placeholder="0.00"
                                    />
                                    <InputError message={errors?.max_salary} />
                                </div>
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="experience_years">{t('jobPostings.form.experience')}</Label>
                                <Input
                                    id="experience_years"
                                    type="number"
                                    min="0"
                                    value={data.experience_years || ''}
                                    onChange={(e) => setData('experience_years', e.target.value === '' ? '' : parseInt(e.target.value) || 0)}
                                    placeholder={t('jobPostings.form.experiencePlaceholder')}
                                />
                                <InputError message={errors?.experience_years} />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="education_level">{t('jobPostings.form.education')}</Label>
                                <Input
                                    id="education_level"
                                    value={data.education_level || ''}
                                    onChange={(e) => setData('education_level', e.target.value)}
                                    placeholder={t('jobPostings.form.educationPlaceholder')}
                                />
                                <InputError message={errors?.education_level} />
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle>{t('jobPostings.form.jobLocation')}</CardTitle>
                            <CardDescription>
                                {t('jobPostings.form.jobLocationDescription')}
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div>
                                    <Label htmlFor="is_remote">{t('jobPostings.form.remote')}</Label>
                                    <p className="text-sm text-muted-foreground">
                                        {t('jobPostings.form.remoteDescription')}
                                    </p>
                                </div>
                                <Switch
                                    id="is_remote"
                                    checked={data.is_remote}
                                    onCheckedChange={(checked) => setData('is_remote', checked)}
                                />
                            </div>

                            {!data.is_remote && (
                                <div className="space-y-2">
                                    <Label htmlFor="location">{t('jobPostings.form.location')}</Label>
                                    <Input
                                        id="location"
                                        value={data.location || ''}
                                        onChange={(e) => setData('location', e.target.value)}
                                        placeholder={t('jobPostings.form.locationPlaceholder')}
                                    />
                                    <InputError message={errors?.location} />
                                </div>
                            )}

                            <div className="space-y-2">
                                <Label htmlFor="target_start_date">{t('jobPostings.form.startDate')}</Label>
                                <Input
                                    id="target_start_date"
                                    type="date"
                                    value={data.target_start_date || ''}
                                    onChange={(e) => setData('target_start_date', e.target.value)}
                                />
                                <InputError message={errors?.target_start_date} />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="closing_date">{t('jobPostings.form.closingDate')}</Label>
                                <Input
                                    id="closing_date"
                                    type="date"
                                    value={data.closing_date || ''}
                                    onChange={(e) => setData('closing_date', e.target.value)}
                                />
                                <InputError message={errors?.closing_date} />
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle>{t('jobPostings.form.status')}</CardTitle>
                            <CardDescription>
                                {t('jobPostings.form.statusDescription')}
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="space-y-2">
                                <Select
                                    value={data.status}
                                    onValueChange={(value) => setData('status', value)}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder={t('jobPostings.form.selectStatus')} />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="draft">{t('jobPostings.status.draft')}</SelectItem>
                                        <SelectItem value="open">{t('jobPostings.status.open')}</SelectItem>
                                        <SelectItem value="closed">{t('jobPostings.status.closed')}</SelectItem>
                                    </SelectContent>
                                </Select>
                                <InputError message={errors?.status} />
                            </div>
                        </CardContent>
                    </Card>

                    <div className="flex flex-col gap-3">
                        <Button type="submit" disabled={processing}>
                            <Save className="h-4 w-4 mr-2" />
                            {processing ? t('jobPostings.form.saving') : t('jobPostings.form.savePosting')}
                        </Button>
                        <Link
                            href={route('dashboard.job-postings.index')}
                            className={buttonVariants({ variant: 'outline' })}
                        >
                            <ArrowLeft className="h-4 w-4 mr-2" />
                            {t('jobPostings.form.backToList')}
                        </Link>
                    </div>
                </div>
            </div>
        </form>
    )
}