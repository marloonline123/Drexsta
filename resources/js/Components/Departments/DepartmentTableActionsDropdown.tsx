import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/Components/Ui/dropdown-menu';
import usePermissions from '@/hooks/use-permissions';
import useTranslation from '@/Hooks/use-translation';
import { Department } from '@/Types/deparments';
import { router } from '@inertiajs/react';
import { Edit, Eye, MoreHorizontal, Trash2 } from 'lucide-react';
import { Button } from '../Ui/button';

interface DepartmentTableActionsDropdownProps {
    department: Department;
    onDelete?: (department: Department) => void;
}

export default function DepartmentTableActionsDropdown({ department, onDelete }: DepartmentTableActionsDropdownProps) {
    const { can } = usePermissions();
    const { translate } = useTranslation();

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="h-8 w-8 p-0">
                    <span className="sr-only">Open menu</span>
                    <MoreHorizontal className="h-4 w-4" />
                </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => router.visit(route('dashboard.departments.show', { department }))}>
                    <Eye className="mr-2 h-4 w-4" />
                    {translate('main.action_options.view')}
                </DropdownMenuItem>
                {can('departments.edit') && (
                    <DropdownMenuItem onClick={() => router.visit(route('dashboard.departments.edit', { department }))}>
                        <Edit className="mr-2 h-4 w-4" />
                        {translate('main.action_options.edit')}
                    </DropdownMenuItem>
                )}
                <DropdownMenuSeparator />
                {can('departments.delete') && (
                    <DropdownMenuItem onClick={() => onDelete && onDelete(department)} className="text-destructive">
                        <Trash2 className="mr-2 h-4 w-4" />
                        {translate('main.action_options.delete')}
                    </DropdownMenuItem>
                )}
            </DropdownMenuContent>
        </DropdownMenu>
    );
}
