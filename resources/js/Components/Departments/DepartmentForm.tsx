import { Input } from '@/Components/Ui/input';
import { Label } from '@/Components/Ui/label';
import { Switch } from '@/Components/Ui/switch';
import { Textarea } from '@/Components/Ui/textarea';
import InputError from '@/Components/input-error';
import { Department } from '@/Types/deparments';
import { Form, Link } from '@inertiajs/react';
import { Save } from 'lucide-react';
import { Button, buttonVariants } from '../Ui/button';
import useTranslation from '@/Hooks/use-translation';
import { User } from '@/Types/user';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/Components/Ui/select';
import { Avatar, AvatarFallback, AvatarImage } from '@/Components/Ui/avatar';

interface DepartmentFormProps {
    action: string;
    department?: Department;
    employees: User[];
    method?: 'post' | 'put' | 'patch';
    onSuccess?: () => void;
}

export default function DepartmentForm({ action, department, employees = [], method = 'post', onSuccess }: DepartmentFormProps) {
    const { translate } = useTranslation();
    return (
        <Form action={action} method={method} onSuccess={onSuccess}>
            {({ processing, errors }) => (
                <div className="space-y-6">
                    <div className="space-y-2">
                        <Label htmlFor="name">
                            {translate('departments.form.labels.name')} <span className="text-destructive">*</span>
                        </Label>
                        <Input id="name" name="name" placeholder={translate('departments.form.placeholder.name')} required autoFocus defaultValue={department?.name || ''} />
                        <InputError message={errors.name} />
                    </div>

                    {/* Description */}
                    <div className="space-y-2">
                        <Label htmlFor="description">{translate('departments.form.labels.description')}</Label>
                        <Textarea
                            id="description"
                            name="description"
                            placeholder={translate('departments.form.placeholder.description')}
                            rows={4}
                            defaultValue={department?.description || ''}
                        />
                        <InputError message={errors.description} />
                    </div>

                    {/* Annual Budget */}
                    <div className="space-y-2">
                        <Label htmlFor="annual_budget">{translate('departments.form.labels.annual_budget')}</Label>
                        <Input
                            id="annual_budget"
                            name="annual_budget"
                            type="number"
                            placeholder={translate('departments.form.placeholder.annual_budget')}
                            min="0"
                            step="0.01"
                            defaultValue={department?.annual_budget || ''}
                        />
                        <InputError message={errors.annual_budget} />
                    </div>

                    <div className="space-y-2">
                        <Label htmlFor="manager_id">
                            {translate('departments.form.labels.manager_id')} <span className="text-destructive">*</span>
                        </Label>
                        <Select 
                            name="manager_id" 
                            defaultValue={department?.manager?.id?.toString() || ''}
                            required
                        >
                            <SelectTrigger>
                                <SelectValue placeholder={translate('main.select')} />
                            </SelectTrigger>
                            <SelectContent>
                                {employees.map((employee) => (
                                    <SelectItem key={employee.id} value={employee.id.toString()}>
                                        <div className="flex items-center gap-2">
                                            <Avatar className="h-6 w-6">
                                                <AvatarImage src={employee.profile_photo_url} />
                                                <AvatarFallback>
                                                    {employee.name.split(' ').map(n => n[0]).join('')}
                                                </AvatarFallback>
                                            </Avatar>
                                            <div>
                                                <div className="font-medium">{employee.name}</div>
                                            </div>
                                        </div>
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                        <InputError message={errors.manager_id} />
                    </div>

                    <div className="flex items-center justify-between">
                        <div className="space-y-0.5">
                            <Label>{translate('departments.form.labels.status')}</Label>
                            <p className="text-sm text-muted-foreground">{translate('departments.form.descriptions.status')}</p>
                        </div>
                        <Switch name="is_active" defaultChecked={department?.is_active ?? true} />
                    </div>

                    {/* Form Actions */}
                    <div className="flex items-center justify-end gap-4 border-t pt-6">
                        <Link href="/dashboard/departments" className={buttonVariants({ variant: 'outline' })}>
                            {translate('departments.form.actions.cancel')}
                        </Link>
                        <Button type="submit" disabled={processing}>
                            <Save className="mr-2 h-4 w-4" />
                            {processing ? translate('departments.form.actions.saving') : department ? translate('departments.form.actions.update') : translate('departments.form.actions.create')}
                        </Button>
                    </div>
                </div>
            )}
        </Form>
    );
}