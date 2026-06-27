import { cn } from '@/Lib/utils';
import { LucideIcon } from 'lucide-react';

interface StatWidgetProps {
    title: string;
    value: string | number;
    icon?: LucideIcon;
    className?: string;
    valueClassName?: string;
    titleClassName?: string;
}

export default function StatWidget({ 
    title, 
    value, 
    icon: Icon,
    className = '',
    valueClassName = '',
    titleClassName = ''
}: StatWidgetProps) {
    return (
        <div className={cn('bg-card rounded-md p-4 shadow-sm border-1 border-border', className)}>
            <div className="flex items-start gap-4">
                {Icon && (
                    <div className="p-2 bg-primary/10 rounded-lg">
                        <Icon className="h-5 w-5 text-primary" />
                    </div>
                )}
                <div className="space-y-1">
                    <p className={cn('text-sm font-medium text-muted-foreground', titleClassName)}>
                        {title}
                    </p>
                    <p className={cn('text-2xl font-bold', valueClassName)}>
                        {value}
                    </p>
                </div>
                
            </div>
        </div>
    );
}