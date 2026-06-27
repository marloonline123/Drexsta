import { Card, CardContent, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Badge } from '@/Components/Ui/badge';
import { Building } from 'lucide-react';
import useTranslation from '@/Hooks/use-translation';
import { Department } from '@/Types/deparments';

interface DepartmentOverviewProps {
    department: Department;
}

export default function DepartmentOverview({ department }: DepartmentOverviewProps) {
    const { translate } = useTranslation();
    
    return (
        <Card>
            <CardHeader>
                <div className="flex items-center gap-4">
                    <div className="h-16 w-16 bg-primary/10 rounded-lg flex items-center justify-center">
                        <Building className="h-8 w-8 text-primary" />
                    </div>
                    <div className="flex-1">
                        <CardTitle className="text-xl">{department.name}</CardTitle>
                        <p className="text-muted-foreground">{department.description}</p>
                        <div className="flex items-center gap-2 mt-2">
                            <Badge variant={department.is_active ? 'default' : 'secondary'}>
                                {department.is_active ? translate('main.active') : translate('main.inactive')}
                            </Badge>
                            <span className="text-sm text-muted-foreground">•</span>
                        </div>
                    </div>
                </div>
            </CardHeader>
        </Card>
    );
}