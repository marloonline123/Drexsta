import { Badge } from '@/Components/Ui/badge';
import { Button } from '@/Components/Ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/Ui/card';
import { StatsCard } from '@/Components/Ui/stats-card';
import AppLayout from '@/Layouts/AppLayout';
import usePermissions from '@/hooks/use-permissions';
import { DashboardProps } from '@/Types/main';
import { type Auth } from '@/Types';
import { Head, usePage } from '@inertiajs/react';
import { useLanguage } from '@/Hooks/use-language';
import {
    Activity,
    AlertCircle,
    BarChart3,
    Bell,
    Calendar,
    CheckCircle,
    Clock,
    CreditCard,
    DollarSign,
    Plus,
    TrendingUp,
    User,
    UserPlus,
    Users,
    Zap,
} from 'lucide-react';

type RecentActivityItem = {
    id: number;
    type: string;
    user: string;
    action: string;
    time: string;
    status: string;
};

const ACTIVITY_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
    leave_request: Calendar,
    employee_added: UserPlus,
    payroll_processed: CreditCard,
    attendance_alert: AlertCircle,
};

export default function Dashboard({ personalStats, recentActivities, quickActions }: DashboardProps) {
    const { t } = useLanguage();
    const page = usePage();
    const { user } = page.props.auth as Auth;
    const { can } = usePermissions();
    const { can } = usePermissions();

    const canViewCompanyMetrics =
        can('employees.view') || can('companies.view');

    const getStatusColor = (status: string) => {
        switch (status.toLowerCase()) {
            case 'present':
            case 'approved':
            case 'completed':
                return 'bg-green-100 text-green-800';
            case 'absent':
            case 'rejected':
                return 'bg-red-100 text-red-800';
            case 'pending':
                return 'bg-yellow-100 text-yellow-800';
            case 'warning':
                return 'bg-orange-100 text-orange-800';
            default:
                return 'bg-gray-100 text-gray-800';
        }
    };

    const getIcon = (iconName: string) => {
        switch (iconName) {
            case 'clock':
                return <Clock className="h-4 w-4" />;
            case 'calendar':
                return <Calendar className="h-4 w-4" />;
            case 'user':
                return <User className="h-4 w-4" />;
            case 'dollar-sign':
                return <DollarSign className="h-4 w-4" />;
            default:
                return <Activity className="h-4 w-4" />;
        }
    };

    // Company-wide stats (mock data until backend provides real data)
    const companyStats = [
        {
            title: t('dashboard.totalEmployees'),
            value: 142,
            change: '+12 this month',
            changeType: 'positive' as const,
            icon: Users,
        },
        {
            title: t('dashboard.activeEmployees'),
            value: 138,
            change: '+5 this week',
            changeType: 'positive' as const,
            icon: Users,
        },
        {
            title: t('dashboard.pendingLeaves'),
            value: 8,
            change: '-2 from yesterday',
            changeType: 'negative' as const,
            icon: Calendar,
        },
        {
            title: t('dashboard.monthlyPayroll'),
            value: '$285,420',
            change: '+3.2% from last month',
            changeType: 'positive' as const,
            icon: DollarSign,
        },
    ];

    // Mock company activities (would come from backend)
    const companyActivities: RecentActivityItem[] = [
        { id: 1, type: 'leave_request', user: 'Sarah Johnson', action: 'submitted a leave request', time: '2 hours ago', status: 'pending' },
        { id: 2, type: 'employee_added', user: 'Admin', action: 'added new employee John Smith', time: '4 hours ago', status: 'completed' },
        { id: 3, type: 'payroll_processed', user: 'System', action: 'processed payroll for March 2024', time: '1 day ago', status: 'completed' },
        { id: 4, type: 'attendance_alert', user: 'Michael Brown', action: 'has been marked as late', time: '2 days ago', status: 'warning' },
    ];

    return (
        <AppLayout>
            <Head title={t('nav.dashboard', 'Dashboard')} />

            <div className="space-y-6 p-6">
                {/* Welcome Section */}
                <div className="flex items-center justify-between animate-in fade-in slide-in-from-bottom duration-500">
                    <div>
                        <h1 className="text-3xl font-bold">{t('dashboard.welcome')}</h1>
                        <p className="text-muted-foreground mt-1">
                            Here's what's happening with your team today.
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        <Button variant="outline" size="sm">
                            <Bell className="h-4 w-4 mr-2" />
                            Notifications
                        </Button>
                        <Button size="sm">
                            <Plus className="h-4 w-4 mr-2" />
                            Quick Add
                        </Button>
                    </div>
                </div>

                {/* ── Personal Stats (visible to all users) ── */}
                <div>
                    <h2 className="text-lg font-semibold mb-3">My Stats</h2>
                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                        {/* Today's Attendance */}
                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">Today's Attendance</CardTitle>
                                <Clock className="h-4 w-4 text-muted-foreground" />
                            </CardHeader>
                            <CardContent>
                                {personalStats.todayAttendance ? (
                                    <div className="space-y-1">
                                        <div className="text-2xl font-bold">{personalStats.todayAttendance.hours_worked}h</div>
                                        <p className="text-xs text-muted-foreground">
                                            {personalStats.todayAttendance.clock_in} – {personalStats.todayAttendance.clock_out}
                                        </p>
                                        <Badge className={getStatusColor(personalStats.todayAttendance.status)}>
                                            {personalStats.todayAttendance.status}
                                        </Badge>
                                    </div>
                                ) : (
                                    <div className="text-2xl font-bold text-muted-foreground">No data</div>
                                )}
                            </CardContent>
                        </Card>

                        {/* Leave Balance */}
                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">Leave Balance</CardTitle>
                                <Calendar className="h-4 w-4 text-muted-foreground" />
                            </CardHeader>
                            <CardContent>
                                <div className="space-y-2">
                                    {Object.keys(personalStats.leaveBalance).length > 0 ? (
                                        Object.entries(personalStats.leaveBalance).map(([type, balance]) => (
                                            <div key={type} className="flex justify-between text-sm">
                                                <span className="capitalize">{type}</span>
                                                <span>
                                                    {typeof balance === 'object' && balance !== null
                                                        ? `${balance.used}/${balance.total}`
                                                        : `${balance} day(s) used`}
                                                </span>
                                            </div>
                                        ))
                                    ) : (
                                        <p className="text-sm text-muted-foreground">No leave data</p>
                                    )}
                                </div>
                            </CardContent>
                        </Card>

                        {/* Monthly Hours */}
                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">Monthly Hours</CardTitle>
                                <TrendingUp className="h-4 w-4 text-muted-foreground" />
                            </CardHeader>
                            <CardContent>
                                <div className="text-2xl font-bold">{personalStats.monthlyHours}h</div>
                                <p className="text-xs text-muted-foreground">This month</p>
                            </CardContent>
                        </Card>

                        {/* Next Payslip */}
                        <Card>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium">Next Payslip</CardTitle>
                                <DollarSign className="h-4 w-4 text-muted-foreground" />
                            </CardHeader>
                            <CardContent>
                                {personalStats.nextPayslip ? (
                                    <div className="space-y-1">
                                        <div className="text-2xl font-bold">${personalStats.nextPayslip.amount}</div>
                                        <p className="text-xs text-muted-foreground">{personalStats.nextPayslip.date}</p>
                                    </div>
                                ) : (
                                    <div className="text-2xl font-bold text-muted-foreground">No data</div>
                                )}
                            </CardContent>
                        </Card>
                    </div>
                </div>

                {/* ── Company-Wide Metrics (managers/admins only) ── */}
                {canViewCompanyMetrics && (
                    <div className="animate-in fade-in slide-in-from-bottom duration-500 delay-100">
                        <h2 className="text-lg font-semibold mb-3">Company Overview</h2>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                            {companyStats.map((stat, index) => (
                                <StatsCard key={index} {...stat} />
                            ))}
                        </div>
                    </div>
                )}

                {/* ── Main Content Grid ── */}
                <div className="grid lg:grid-cols-3 gap-6">
                    {/* Recent Activities (personal for all; company section for admins) */}
                    <div className="lg:col-span-2 space-y-6">
                        {/* Personal recent activities */}
                        <Card className="animate-in fade-in slide-in-from-bottom duration-500 delay-200">
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <Activity className="h-5 w-5" />
                                    My Recent Activity
                                </CardTitle>
                                <CardDescription>Your latest attendance and leave activity</CardDescription>
                            </CardHeader>
                            <CardContent>
                                <div className="space-y-4">
                                    {recentActivities && recentActivities.length > 0 ? (
                                        recentActivities.map((activity, index) => (
                                            <div key={index} className="flex items-center space-x-4">
                                                <div className="flex-1 space-y-1">
                                                    <p className="text-sm leading-none font-medium">{activity.description}</p>
                                                    <p className="text-sm text-muted-foreground">{activity.date}</p>
                                                </div>
                                                <Badge className={getStatusColor(activity.status)}>{activity.status}</Badge>
                                            </div>
                                        ))
                                    ) : (
                                        <p className="text-sm text-muted-foreground">No recent activities</p>
                                    )}
                                </div>
                            </CardContent>
                        </Card>

                        {/* Company-wide activities (managers/admins only) */}
                        {canViewCompanyMetrics && (
                            <Card className="animate-in fade-in slide-in-from-bottom duration-500 delay-200">
                                <CardHeader>
                                    <CardTitle className="flex items-center gap-2">
                                        <Activity className="h-5 w-5" />
                                        {t('dashboard.recentActivities')}
                                    </CardTitle>
                                    <CardDescription>Latest updates from your organization</CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    {companyActivities.map((activity) => {
                                        const IconComponent = ACTIVITY_ICONS[activity.type] ?? Activity;
                                        return (
                                            <div key={activity.id} className="flex items-start gap-4 p-3 rounded-lg hover:bg-muted/50 transition-colors">
                                                <div className="p-2 rounded-lg bg-primary/10">
                                                    <IconComponent className="h-4 w-4 text-primary" />
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-sm font-medium">
                                                        <span className="font-semibold">{activity.user}</span>
                                                        {' '}{activity.action}
                                                    </p>
                                                    <div className="flex items-center gap-2 mt-1">
                                                        <span className="text-xs text-muted-foreground">{activity.time}</span>
                                                        <Badge
                                                            variant={
                                                                activity.status === 'completed'
                                                                    ? 'default'
                                                                    : activity.status === 'pending'
                                                                    ? 'secondary'
                                                                    : 'destructive'
                                                            }
                                                            className="text-xs"
                                                        >
                                                            {activity.status}
                                                        </Badge>
                                                    </div>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </CardContent>
                            </Card>
                        )}
                    </div>

                    {/* Quick Actions (visible to all) */}
                    <div className="animate-in fade-in slide-in-from-bottom duration-500 delay-300">
                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <Zap className="h-5 w-5" />
                                    {t('dashboard.quickActions')}
                                </CardTitle>
                                <CardDescription>Common tasks you can perform</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-3">
                                {quickActions.map((action, index) => (
                                    <Button
                                        key={index}
                                        variant="ghost"
                                        className="w-full justify-start h-auto p-4"
                                        asChild
                                    >
                                        <a href={action.url}>
                                            <div className="flex items-center gap-3">
                                                <div className="p-2 rounded-lg bg-primary/10 text-primary">
                                                    {getIcon(action.icon)}
                                                </div>
                                                <div className="text-left">
                                                    <div className="font-semibold text-sm">{action.title}</div>
                                                </div>
                                            </div>
                                        </a>
                                    </Button>
                                ))}
                            </CardContent>
                        </Card>
                    </div>
                </div>

                {/* ── Performance Overview (managers/admins only) ── */}
                {canViewCompanyMetrics && (
                    <div className="animate-in fade-in slide-in-from-bottom duration-500 delay-400">
                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <TrendingUp className="h-5 w-5" />
                                    Performance Overview
                                </CardTitle>
                                <CardDescription>Key metrics and trends for this month</CardDescription>
                            </CardHeader>
                            <CardContent>
                                <div className="grid md:grid-cols-3 gap-6">
                                    <div className="text-center p-4 rounded-lg bg-green-50 dark:bg-green-950">
                                        <TrendingUp className="h-8 w-8 text-green-600 mx-auto mb-2" />
                                        <div className="text-2xl font-bold text-green-600">94%</div>
                                        <div className="text-sm text-muted-foreground">Attendance Rate</div>
                                    </div>
                                    <div className="text-center p-4 rounded-lg bg-blue-50 dark:bg-blue-950">
                                        <CheckCircle className="h-8 w-8 text-blue-600 mx-auto mb-2" />
                                        <div className="text-2xl font-bold text-blue-600">87%</div>
                                        <div className="text-sm text-muted-foreground">Task Completion</div>
                                    </div>
                                    <div className="text-center p-4 rounded-lg bg-purple-50 dark:bg-purple-950">
                                        <Users className="h-8 w-8 text-purple-600 mx-auto mb-2" />
                                        <div className="text-2xl font-bold text-purple-600">4.8</div>
                                        <div className="text-sm text-muted-foreground">Employee Satisfaction</div>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    </div>
                )}
            </div>
        </AppLayout>
    );
}
