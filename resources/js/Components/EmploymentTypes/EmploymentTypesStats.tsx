import { Card, CardContent, CardHeader, CardTitle } from '@/Components/Ui/card';
import { PaginatedData } from '@/Types/global';
import { EmploymentType } from '@/Types/employment-types';
import useTranslation from '@/Hooks/use-translation';

interface EmploymentTypesStatsProps {
    employmentTypes: PaginatedData<EmploymentType>;
}

export default function EmploymentTypesStats({ employmentTypes }: EmploymentTypesStatsProps) {
    const { translate } = useTranslation();
    const employmentTypesData = employmentTypes.data;
    const total = employmentTypes.meta?.total || 0;
    const activeCount = employmentTypesData.filter((et: EmploymentType) => et.is_active).length;
    const inactiveCount = employmentTypesData.filter((et: EmploymentType) => !et.is_active).length;

    return (
        <div className="grid gap-4 md:grid-cols-3">
            <Card>
                <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                        {translate('employment_types.totalEmploymentTypes')}
                    </CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                    <div className="text-2xl font-bold">{total}</div>
                </CardContent>
            </Card>
            
            <Card>
                <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                        {translate('employment_types.activeEmploymentTypes')}
                    </CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                    <div className="text-2xl font-bold text-green-600">
                        {activeCount}
                    </div>
                </CardContent>
            </Card>
            
            <Card>
                <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">
                        {translate('employment_types.inactiveEmploymentTypes')}
                    </CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                    <div className="text-2xl font-bold text-red-600">
                        {inactiveCount}
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}