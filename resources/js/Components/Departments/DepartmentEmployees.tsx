import { Card, CardContent, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Avatar, AvatarImage, AvatarFallback } from '@/Components/Ui/avatar';
import { Badge } from '@/Components/Ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/Ui/table';
import { Crown, User } from 'lucide-react';
import useTranslation from '@/Hooks/use-translation';
import { Department } from '@/Types/deparments';

interface DepartmentEmployeesProps {
    department: Department;
}

export default function DepartmentEmployees({ department }: DepartmentEmployeesProps) {
    const { translate } = useTranslation();
    
    return (
        <Card>
            <CardHeader>
                <CardTitle>{translate('departments.pages.show.members_section')}</CardTitle>
            </CardHeader>
            <CardContent>
                <div className="rounded-md border">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>{translate('main.headers.employee')}</TableHead>
                                <TableHead>{translate('main.headers.email')}</TableHead>
                                <TableHead>{translate('main.headers.role')}</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {department.employees.map((employee) => (
                                <TableRow key={employee.id}>
                                    <TableCell>
                                        <div className="flex items-center gap-3">
                                            <Avatar className="h-8 w-8">
                                                <AvatarImage src={employee.profile_photo_url} />
                                                <AvatarFallback>
                                                    {employee.name.split(' ').map(n => n[0]).join('')}
                                                </AvatarFallback>
                                            </Avatar>
                                            <span className="font-medium">{employee.name}</span>
                                        </div>
                                    </TableCell>
                                    <TableCell>{employee.email}</TableCell>
                                    <TableCell>
                                        <Badge variant={employee.department_role === 'manager' ? 'default' : 'outline'}>
                                            {employee.department_role === 'manager' ? (
                                                <>
                                                    <Crown className="h-3 w-3 mr-1" />
                                                    {translate('departments.fields.manager')}
                                                </>
                                            ) : (
                                                <>
                                                    <User className="h-3 w-3 mr-1" />
                                                    {translate('departments.fields.employees')}
                                                </>
                                            )}
                                        </Badge>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </div>
            </CardContent>
        </Card>
    );
}