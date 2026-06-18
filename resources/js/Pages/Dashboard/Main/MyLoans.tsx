import { Badge } from '@/Components/Ui/badge';
import { Button } from '@/Components/Ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/Ui/table';
import AppLayout from '@/Layouts/AppLayout';
import { LoansPageProps } from '@/Types/main';
import { Head } from '@inertiajs/react';
import { Calendar, DollarSign, Plus } from 'lucide-react';

export default function MyLoans({ loans }: LoansPageProps) {
    const getStatusColor = (status: string) => {
        switch (status.toLowerCase()) {
            case 'active':
                return 'bg-blue-100 text-blue-800';
            case 'completed':
                return 'bg-green-100 text-green-800';
            case 'overdue':
                return 'bg-red-100 text-red-800';
            default:
                return 'bg-gray-100 text-gray-800';
        }
    };

    const formatCurrency = (amount: number) => {
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: 'USD',
        }).format(amount);
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
            <Head title="My Loans" />

            <div className="space-y-6">
                {/* Summary Cards */}
                <div className="grid gap-4 md:grid-cols-3">
                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <CardTitle className="text-sm font-medium">Active Loans</CardTitle>
                            <DollarSign className="h-4 w-4 text-muted-foreground" />
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">{loans.filter((loan) => loan.status === 'active').length}</div>
                            <p className="text-xs text-muted-foreground">Currently active</p>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <CardTitle className="text-sm font-medium">Total Outstanding</CardTitle>
                            <DollarSign className="h-4 w-4 text-muted-foreground" />
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">
                                {formatCurrency(
                                    loans.filter((loan) => loan.status === 'active').reduce((sum, loan) => sum + loan.remaining_amount, 0),
                                )}
                            </div>
                            <p className="text-xs text-muted-foreground">Amount remaining</p>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <CardTitle className="text-sm font-medium">Next Payment</CardTitle>
                            <Calendar className="h-4 w-4 text-muted-foreground" />
                        </CardHeader>
                        <CardContent>
                            <div className="text-2xl font-bold">
                                {loans.find((loan) => loan.status === 'active' && loan.next_payment_date)
                                    ? formatDate(loans.find((loan) => loan.status === 'active' && loan.next_payment_date)!.next_payment_date!)
                                    : 'No upcoming'}
                            </div>
                            <p className="text-xs text-muted-foreground">Due date</p>
                        </CardContent>
                    </Card>
                </div>

                {/* Request Loan Button */}
                <div className="flex justify-end">
                    <Button>
                        <Plus className="mr-2 h-4 w-4" />
                        Request Loan
                    </Button>
                </div>

                {/* Loans Table */}
                <Card>
                    <CardHeader>
                        <CardTitle>Loan History</CardTitle>
                        <CardDescription>All your loan requests and payment tracking</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Amount</TableHead>
                                    <TableHead>Remaining</TableHead>
                                    <TableHead>Monthly Payment</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Created Date</TableHead>
                                    <TableHead>Next Payment</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {loans.length > 0 ? (
                                    loans.map((loan) => (
                                        <TableRow key={loan.id}>
                                            <TableCell className="font-medium">{formatCurrency(loan.amount)}</TableCell>
                                            <TableCell>{loan.status === 'completed' ? '$0.00' : formatCurrency(loan.remaining_amount)}</TableCell>
                                            <TableCell>{formatCurrency(loan.monthly_payment)}</TableCell>
                                            <TableCell>
                                                <Badge className={getStatusColor(loan.status)}>{loan.status}</Badge>
                                            </TableCell>
                                            <TableCell>{formatDate(loan.created_at)}</TableCell>
                                            <TableCell>{loan.next_payment_date ? formatDate(loan.next_payment_date) : 'N/A'}</TableCell>
                                        </TableRow>
                                    ))
                                ) : (
                                    <TableRow>
                                        <TableCell colSpan={6} className="text-center text-muted-foreground">
                                            No loan records found
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
