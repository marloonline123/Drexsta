interface PageHeaderProps {
    title: string | React.ReactNode;
    description?: string | React.ReactNode;
    action?: string | React.ReactNode;
}

export default function PageHeader({ title, description, action }: PageHeaderProps) {
    return (
        <div className="flex items-center justify-between">
            <div>
                {title && typeof title === 'string' ? <h1 className="flex items-center gap-2 text-3xl font-bold tracking-tight">{title}</h1> : title}
                {description && <p className="text-muted-foreground">{description}</p>}
            </div>

            {action && <div>{action}</div>}
        </div>
    );
}
