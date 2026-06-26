import { Company } from '@/Types/companies'
import { Button } from '@/Components/Ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/Components/Ui/dropdown-menu';
import {
    MoreVertical,
    Edit,
    Trash2,
    Eye,
    MapPin,
    Users,
    Phone,
    Mail,
    Calendar,
    CheckCircle,
    XCircle,
} from 'lucide-react';
import { Avatar, AvatarFallback, AvatarImage } from '@/Components/Ui/avatar';
import { Card, CardContent, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Badge } from '@/Components/Ui/badge';
import { useState } from 'react';
import { useLanguage } from '@/Hooks/use-language';
import { router, usePage } from '@inertiajs/react';
import DeleteCompanyModal from './DeleteCompanyModal';
import usePermissions from '@/hooks/use-permissions';
import { Auth } from '@/Types';

export default function CompanyCard({ company }: { company: Company }) {
    const [showDeleteModal, setShowDeleteModal] = useState<boolean>(false);
    const { t } = useLanguage();
    const { user } = usePage().props.auth as Auth;
    const { can } = usePermissions();
    const { can } = usePermissions();

    const getStatusBadge = (isActive: boolean) => {
        return isActive ? (
            <Badge className="bg-green-100 text-green-800">
                <CheckCircle className="h-3 w-3 mr-1" />
                {t('companies.active')}
            </Badge>
        ) : (
            <Badge className="bg-red-100 text-red-800">
                <XCircle className="h-3 w-3 mr-1" />
                {t('companies.inactive')}
            </Badge>
        );
    };

    return (
        <Card className="hover:shadow-lg transition-shadow">
            <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <Avatar className="h-12 w-12">
                            <AvatarImage src={company.logo_url || ""} className='object-cover' alt={company.name} />
                            <AvatarFallback className="bg-primary/10 text-primary">
                                {company.name.split(' ').map(n => n[0]).join('').toUpperCase()}
                            </AvatarFallback>
                        </Avatar>
                        <div>
                            <CardTitle className="text-lg">{company.name}</CardTitle>
                            <p className="text-sm text-muted-foreground">{company.industry}</p>
                        </div>
                    </div>
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                                <MoreVertical className="h-4 w-4" />
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => router.visit(route('dashboard.companies.show', company.slug))}>
                                <Eye className="h-4 w-4 mr-2" />
                                {t('common.view')}
                            </DropdownMenuItem>
                            {can('companies.edit') && (
                                <DropdownMenuItem onClick={() => router.visit(route('dashboard.companies.edit', company.slug))}>
                                    <Edit className="h-4 w-4 mr-2" />
                                    {t('common.edit')}
                                </DropdownMenuItem>
                            )}
                            {can('companies.delete') && (
                                <DropdownMenuItem onClick={() => setShowDeleteModal(true)}>
                                    <Trash2 className="h-4 w-4 mr-2" />
                                    {t('common.delete')}
                                </DropdownMenuItem>
                            )}
                        </DropdownMenuContent>
                    </DropdownMenu>
                </div>
                <div className="flex items-center gap-2">
                    {getStatusBadge(company.is_active)}
                </div>
            </CardHeader>
            <CardContent>
                <div className="space-y-3">
                    <div className="flex items-center gap-2 text-sm">
                        <Users className="h-4 w-4 text-muted-foreground" />
                        <span>{company.employees_count} {t('companies.employeesCount')}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                        <Mail className="h-4 w-4 text-muted-foreground" />
                        <span className="truncate">{company.email}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                        <Phone className="h-4 w-4 text-muted-foreground" />
                        <span>{company.phone}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                        <MapPin className="h-4 w-4 text-muted-foreground" />
                        <span className="truncate">{company.address}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Calendar className="h-4 w-4" />
                        <span>{t('companies.establishedDate')}: {company.established_date}</span>
                    </div>
                </div>
            </CardContent>

            {/* Delete Modal */}
            <DeleteCompanyModal company={company} showDeleteModal={showDeleteModal} setShowDeleteModal={setShowDeleteModal} />
        </Card>
    )
}
