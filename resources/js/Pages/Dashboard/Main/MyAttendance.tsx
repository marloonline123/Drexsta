import { Badge } from '@/Components/Ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/Ui/table';
import AppLayout from '@/Layouts/AppLayout';
import { AttendancePageProps } from '@/Types/main';
import { Head } from '@inertiajs/react';
import { Calendar, Clock, TrendingUp } from 'lucide-react';

export default function MyAttendance({ attendances, monthlySummary }: AttendancePageProps) {
    const getStatusColor = (status: string) => {
        switch (status.toLowerCase()) {
            case 'present':
                return 'bg-green-100 text-green-800';
            case 'absent':
                return 'bg-red-100 text-red-800';
            case 'late':
                return 'bg-yellow-100 text-yellow-800';
            default:
                return 'bg-gray-100 text-gray-800';
        }
    };

    const formatDate = (dateString: string) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            weekday: 'short',
            year: 'numeric',
            month: 'short',
            day: 'numeric',
        });
    };

    return (
        <AppLayout>
            <Head title="My Attendance" />

            <div className="space-y-6">
                {/* Monthly Summary Cards */}
                <div className="grid gap-4 md:grid-cols-3">
                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <CardTitle className="text-sm font-medium">Total Hours</CardTitle>
                            <Clock className="h-4 w-4 text-muted-foreground" />
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">{monthlySummary.total_hours}h</div>
                            <p className="text-xs text-muted-foreground">This month</p>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <CardTitle className="text-sm font-medium">Total Days</CardTitle>
                            <Calendar className="h-4 w-4 text-muted-foreground" />
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">{monthlySummary.total_days}</div>
                            <p className="text-xs text-muted-foreground">Working days</p>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <CardTitle className="text-sm font-medium">Attendance Rate</CardTitle>
                            <TrendingUp className="h-4 w-4 text-muted-foreground" />
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">{monthlySummary.attendance_rate}%</div>
                            <p className="text-xs text-muted-foreground">This month</p>
                        </CardContent>
                    </Card>
                </div>

                {/* Attendance Records Table */}
                <Card>
                    <CardHeader>
                        <CardTitle>Attendance Records</CardTitle>
                        <CardDescription>Your daily attendance records for this month</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Date</TableHead>
                                    <TableHead>Clock In</TableHead>
                                    <TableHead>Clock Out</TableHead>
                                    <TableHead>Hours Worked</TableHead>
                                    <TableHead>Status</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {attendances.length > 0 ? (
                                    attendances.map((attendance) => (
                                        <TableRow key={attendance.id}>
                                            <TableCell className="font-medium">{formatDate(attendance.date)}</TableCell>
                                            <TableCell>{attendance.clock_in}</TableCell>
                                            <TableCell>{attendance.clock_out}</TableCell>
                                            <TableCell>{attendance.hours_worked}h</TableCell>
                                            <TableCell>
                                                <Badge className={getStatusColor(attendance.status)}>{attendance.status}</Badge>
                                            </TableCell>
                                        </TableRow>
                                    ))
                                ) : (
                                    <TableRow>
                                        <TableCell colSpan={5} className="text-center text-muted-foreground">
                                            No attendance records found
                                        </TableCell>
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    </CardContent>
                </Card>
            </div>
        </AppLayout>
    );
}
