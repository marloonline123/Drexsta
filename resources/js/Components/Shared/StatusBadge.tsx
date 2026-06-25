import { Badge } from '@/Components/Ui/badge';
import { cn } from '@/Lib/utils';
import useTranslation from '@/Hooks/use-translation';

interface StatusBadgeProps {
    status: string | boolean;
    trueText?: string;
    falseText?: string;
}

export function StatusBadge({ status, trueText, falseText }: StatusBadgeProps) {
    const { translate } = useTranslation();
    
    // Use translated defaults if not provided
    const defaultTrueText = trueText ?? translate('main.active');
    const defaultFalseText = falseText ?? translate('main.inactive');
    if (typeof status === 'boolean') {
        return (
            <Badge variant={status ? 'default' : 'secondary'} className={cn("overflow-hidden", !status && "bg-neutral-100 text-neutral-500 hover:bg-neutral-100 dark:bg-neutral-800 dark:text-neutral-400")}>
                {status ? defaultTrueText : defaultFalseText}
            </Badge>
        );
    }

    const s = status.toLowerCase();
    let variant: 'default' | 'secondary' | 'destructive' | 'outline' = 'default';
    let className = '';

    if (['paid', 'active', 'completed', 'success'].includes(s)) {
        variant = 'default';
        className = 'bg-green-500 hover:bg-green-600 text-white';
    } else if (['pending', 'processing'].includes(s)) {
        variant = 'secondary';
        className = 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-400';
    } else if (['overdue', 'cancelled', 'failed', 'inactive'].includes(s)) {
        variant = 'destructive';
    }

    return (
        <Badge variant={variant} className={cn("capitalize overflow-hidden", className)}>
            {status}
        </Badge>
    );
}
