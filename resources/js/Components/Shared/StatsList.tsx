import { cn } from '@/Lib/utils';

interface StatsListProps {
    children: React.ReactNode;
    className?: string;
    gridClassName?: string;
}

export default function StatsList({ 
    children, 
    className = '',
    gridClassName = 'grid grid-cols-1 md:grid-cols-3 gap-4'
}: StatsListProps) {
    return (
        <div className={cn(gridClassName, className)}>
            {children}
        </div>
    );
}