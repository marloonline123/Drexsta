import { Card, CardContent, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Avatar, AvatarImage, AvatarFallback } from '@/Components/Ui/avatar';
import { Badge } from '@/Components/Ui/badge';
import { Mail } from 'lucide-react';
import useTranslation from '@/Hooks/use-translation';
import { Department } from '@/Types/deparments';

interface DepartmentManagerProps {
    department: Department;
}

export default function DepartmentManager({ department }: DepartmentManagerProps) {
    const { translate } = useTranslation();
    
    return (
        <Card>
            <CardHeader>
                <CardTitle>{translate('departments.pages.show.manager_section')}</CardTitle>
            </CardHeader>
            <CardContent>
                <div className="flex items-center gap-4">
                    <Avatar className="h-12 w-12">
                        <AvatarImage src={department.manager?.profile_photo_url} />
                        <AvatarFallback>
                            {department.manager?.name.split(' ').map(n => n[0]).join('')}
                        </AvatarFallback>
                    </Avatar>
                    <div className="flex-1">
                        <h3 className="font-semibold">{department.manager?.name}</h3>
                        <div className="flex items-center gap-2 mt-1">
                            <Mail className="h-4 w-4 text-muted-foreground" />
                            <span className="text-sm text-muted-foreground">{department.manager?.email}</span>
                        </div>
                    </div>
                    <Badge variant="outline">{translate('departments.fields.manager')}</Badge>
                </div>
            </CardContent>
        </Card>
    );
}