import { Badge } from '@/Components/Ui/badge';
import { Button } from '@/Components/Ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/Ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/Ui/table';
import AppLayout from '@/Layouts/AppLayout';
import { PayrollPageProps } from '@/Types/main';
import { Head } from '@inertiajs/react';
import { DollarSign, Download, Eye } from 'lucide-react';

export default function MyPayroll({ payslips }: PayrollPageProps) {
    const formatCurrency = (amount: number) => {
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: 'USD',
        }).format(amount);
    };

    const formatDate = (dateString: string) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
        });
    };

    return (
        <AppLayout>
            <Head title="My Payroll" />

            <div className="space-y-6">
                {/* Latest Payslip Card */}
                {payslips.length > 0 && (
                    <Card className="border-primary">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <DollarSign className="h-5 w-5" />
                                Latest Payslip
                            </CardTitle>
                            <CardDescription>Your most recent salary payment</CardDescription>
                        </CardHeader>
                        <CardContent>
                            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                                <div>
                                    <p className="text-sm font-medium text-muted-foreground">Period</p>
                                    <p className="text-lg font-semibold">{payslips[0].period}</p>
                                </div>
                                <div>
                                    <p className="text-sm font-medium text-muted-foreground">Net Salary</p>
                                    <p className="text-lg font-semibold text-green-600">{formatCurrency(payslips[0].net_salary)}</p>
                                </div>
                                <div>
                                    <p className="text-sm font-medium text-muted-foreground">Payment Date</p>
                                    <p className="text-lg font-semibold">{formatDate(payslips[0].payment_date)}</p>
                                </div>
                                <div>
                                    <p className="text-sm font-medium text-muted-foreground">Payment Method</p>
                                    <p className="text-lg font-semibold">{payslips[0].payment_method}</p>
                                </div>
                            </div>
                            <div className="mt-4 flex gap-2">
                                <Button size="sm">
                                    <Eye className="mr-2 h-4 w-4" />
                                    View Details
                                </Button>
                                <Button size="sm" variant="outline">
                                    <Download className="mr-2 h-4 w-4" />
                                    Download
                                </Button>
                            </div>
                        </CardContent>
                    </Card>
                )}

                {/* Payslip History Table */}
                <Card>
                    <CardHeader>
                        <CardTitle>Payslip History</CardTitle>
                        <CardDescription>All your salary payment records</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Period</TableHead>
                                    <TableHead>Gross Salary</TableHead>
                                    <TableHead>Deductions</TableHead>
                                    <TableHead>Bonuses</TableHead>
                                    <TableHead>Net Salary</TableHead>
                                    <TableHead>Payment Date</TableHead>
                                    <TableHead>Payment Method</TableHead>
                                    <TableHead>Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {payslips.length > 0 ? (
                                    payslips.map((payslip) => (
                                        <TableRow key={payslip.id}>
                                            <TableCell className="font-medium">{payslip.period}</TableCell>
                                            <TableCell>{formatCurrency(payslip.gross_salary)}</TableCell>
                                            <TableCell className="text-red-600">-{formatCurrency(payslip.deductions)}</TableCell>
                                            <TableCell className="text-green-600">+{formatCurrency(payslip.bonuses)}</TableCell>
                                            <TableCell className="font-semibold">{formatCurrency(payslip.net_salary)}</TableCell>
                                            <TableCell>{formatDate(payslip.payment_date)}</TableCell>
                                            <TableCell>
                                                <Badge variant="outline">{payslip.payment_method}</Badge>
                                            </TableCell>
                                            <TableCell>
                                                <div className="flex gap-2">
                                                    <Button size="sm" variant="ghost">
                                                        <Eye className="h-4 w-4" />
                                                    </Button>
                                                    <Button size="sm" variant="ghost">
                                                        <Download className="h-4 w-4" />
                                                    </Button>
                                                </div>
                                            </TableCell>
                                        </TableRow>
                                    ))
                                ) : (
                                    <TableRow>
                                        <TableCell colSpan={8} className="text-center text-muted-foreground">
                                            No payslip records found
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
