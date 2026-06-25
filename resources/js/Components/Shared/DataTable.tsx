import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/Ui/table';
import { cn } from '@/Lib/utils';
import { ReactNode } from 'react';

interface Column<T> {
    header: string;
    accessorKey?: keyof T;
    cell?: (item: T) => ReactNode;
    className?: string;
}

interface DataTableProps<T> {
    data: T[];
    columns: Column<T>[];
}

export function DataTable<T>({ data, columns }: DataTableProps<T>) {
    return (
        <div className="rounded-md border border-neutral-200 dark:border-neutral-800">
            <Table>
                <TableHeader>
                    <TableRow>
                        {columns.map((column, i) => (
                            <TableHead key={i} className={cn('text-start', column.className)}>
                                {column.header}
                            </TableHead>
                        ))}
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {data.map((item, i) => (
                        <TableRow key={i}>
                            {columns.map((column, j) => (
                                <TableCell key={j} className={column.className}>
                                    {column.cell ? column.cell(item) : (item[column.accessorKey as keyof T] as ReactNode)}
                                </TableCell>
                            ))}
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </div>
    );
}
