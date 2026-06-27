import { formatCurrency } from '@/Lib/utils';
import { Department } from '@/Types/deparments';
import { PaginatedData } from '@/Types/global';
import { Building, Crown, User, Users } from 'lucide-react';
import useTranslation from '@/Hooks/use-translation';
import StatWidget from '@/Components/Shared/StatWidget';
import StatsList from '@/Components/Shared/StatsList';

export default function DepartmentsStats({ departments }: { departments: PaginatedData<Department> }) {
    const { translate } = useTranslation();
    const departmentsData: Department[] = departments.data || [];
    return (
        <StatsList>
            <StatWidget 
                title={translate('departments.totalDepartments')}
                value={departments.meta?.total ?? 0}
                icon={Building}
            />
            <StatWidget 
                title={translate('departments.activeDepartments')}
                value={departmentsData.filter(d => d.is_active).length}
                icon={Crown}
                valueClassName="text-green-600"
            />
            <StatWidget 
                title={translate('departments.fields.employees')}
                value={(departments.meta as any)?.employees_count ?? 0}
                icon={Users}
            />
        </StatsList>
    )
}
