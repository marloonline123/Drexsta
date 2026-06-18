import { Badge } from '@/Components/Ui/badge';
import { Button } from '@/Components/Ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/Ui/table';
import AppLayout from '@/Layouts/AppLayout';
import { LeavesPageProps } from '@/Types/main';
import { Head } from '@inertiajs/react';
import { Calendar, Plus } from 'lucide-react';

export default function MyLeaves({ leaves, leaveBalance }: LeavesPageProps) {
    const getStatusColor = (status: string) => {
        switch (status.toLowerCase()) {
            case 'approved':
                return 'bg-green-100 text-green-800';
            case 'rejected':
                return 'bg-red-100 text-red-800';
            case 'pending':
                return 'bg-yellow-100 text-yellow-800';
            default:
                return 'bg-gray-100 text-gray-800';
        }
    };

    const formatDate = (dateString: string) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
        });
    };

    return (
        <AppLayout>
            <Head title="My Leaves" />

            <div className="space-y-6">
                {/* Leave Balance Cards */}
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                    {Object.entries(leaveBalance).map(([type, balance]: [string, { used: number; total: number }]) => (
                        <Card key={type}>
                            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                <CardTitle className="text-sm font-medium capitalize">{type} Leave</CardTitle>
                                <Calendar className="h-4 w-4 text-muted-foreground" />
                            </CardHeader>
                            <CardContent>
                                <div className="text-2xl font-bold">
                                    {balance.used}/{balance.total}
                                </div>
                                <p className="text-xs text-muted-foreground">Days used / Total</p>
                            </CardContent>
                        </Card>
                    ))}
                </div>

                {/* Request Leave Button */}
                <div className="flex justify-end">
                    <Button>
                        <Plus className="mr-2 h-4 w-4" />
                        Request Leave
                    </Button>
                </div>

                {/* Leave Requests Table */}
                <Card>
                    <CardHeader>
                        <CardTitle>Leave Requests</CardTitle>
                        <CardDescription>Your leave request history and current status</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Type</TableHead>
                                    <TableHead>Start Date</TableHead>
                                    <TableHead>End Date</TableHead>
                                    <TableHead>Days</TableHead>
                                    <TableHead>Reason</TableHead>
                                    <TableHead>Status</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {leaves.length > 0 ? (
                                    leaves.map((leave) => (
                                        <TableRow key={leave.id}>
                                            <TableCell className="font-medium capitalize">{leave.type}</TableCell>
                                            <TableCell>{formatDate(leave.start_date)}</TableCell>
                                            <TableCell>{formatDate(leave.end_date)}</TableCell>
                                            <TableCell>{leave.days}</TableCell>
                                            <TableCell className="max-w-xs truncate">{leave.reason}</TableCell>
                                            <TableCell>
                                                <Badge className={getStatusColor(leave.status)}>{leave.status}</Badge>
                                            </TableCell>
                                        </TableRow>
                                    ))
                                ) : (
                                    <TableRow>
                                        <TableCell colSpan={6} className="text-center text-muted-foreground">
                                            No leave requests found
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
