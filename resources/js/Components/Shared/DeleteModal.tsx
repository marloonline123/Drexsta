import * as React from 'react';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/Components/Ui/dialog';
import { Button } from '@/Components/Ui/button';
import { useLanguage } from '@/Hooks/use-language';
import { AlertTriangle, Trash2, Loader2 } from 'lucide-react';
import useTranslation from '@/Hooks/use-translation';

interface DeleteModalProps {
    /** Whether the modal is open */
    open: boolean;
    /** Function to call when modal should close */
    onOpenChange: (open: boolean) => void;
    /** Function to call when delete action is confirmed */
    onConfirm: () => void | Promise<void>;
    /** Title of the modal */
    title?: string;
    /** Description text for the modal */
    description?: string;
    /** Custom children to display instead of default content */
    children?: React.ReactNode;
    /** Text for the action (delete) button */
    actionButtonText?: string;
    /** Text for the cancel button */
    cancelButtonText?: string;
    /** Whether the action is currently loading */
    loading?: boolean;
    /** Custom icon to display */
    icon?: React.ReactNode;
    /** Variant of the action button */
    actionVariant?: 'destructive' | 'default' | 'outline' | 'secondary' | 'ghost' | 'link';
    /** Size of the modal */
    size?: 'sm' | 'md' | 'lg' | 'xl';
    /** Whether to show the default warning icon */
    showIcon?: boolean;
}

export function DeleteModal({
    open,
    onOpenChange,
    onConfirm,
    title,
    description,
    children,
    actionButtonText,
    cancelButtonText,
    loading = false,
    icon,
    actionVariant = 'destructive',
    size = 'md',
    showIcon = true,
}: DeleteModalProps) {
    const { translate } = useTranslation();

    const handleConfirm = async () => {
        try {
            await onConfirm();
        } catch (error) {
            // Let the parent component handle errors
            console.error('Delete action failed:', error);
        }
    };

    const handleCancel = () => {
        if (!loading) {
            onOpenChange(false);
        }
    };

    const handleOpenChange = (newOpen: boolean) => {
        if (!loading) {
            onOpenChange(newOpen);
        }
    };

    // Default values
    const modalTitle = title || translate('main.confirmDelete') || 'Confirm Delete';
    const modalDescription = description || translate('main.deleteWarning') || 'This action cannot be undone. Are you sure you want to proceed?';
    const actionText = actionButtonText || translate('main.delete') || 'Delete';
    const cancelText = cancelButtonText || translate('main.cancel') || 'Cancel';

    // Size classes
    const sizeClasses = {
        sm: 'sm:max-w-sm',
        md: 'sm:max-w-md',
        lg: 'sm:max-w-lg',
        xl: 'sm:max-w-xl',
    };

    return (
        <Dialog open={open} onOpenChange={handleOpenChange}>
            <DialogContent className={`${sizeClasses[size]} max-w-[calc(100%-2rem)]`}>
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-3">
                        {showIcon && (
                            <div className="flex-shrink-0">
                                {icon || (
                                    <div className="flex h-10 w-10 items-center justify-center rounded-full bg-destructive/10">
                                        <AlertTriangle className="h-5 w-5 text-destructive" />
                                    </div>
                                )}
                            </div>
                        )}
                        <span>{modalTitle}</span>
                    </DialogTitle>
                    
                    {!children && (
                        <DialogDescription className="text-left">
                            {modalDescription}
                        </DialogDescription>
                    )}
                </DialogHeader>

                {children && (
                    <div className="py-4">
                        {children}
                    </div>
                )}

                <DialogFooter className="flex flex-col-reverse gap-2 sm:flex-row sm:gap-3">
                    <Button
                        variant="outline"
                        onClick={handleCancel}
                        disabled={loading}
                        className="w-full sm:w-auto"
                    >
                        {cancelText}
                    </Button>
                    <Button
                        variant={actionVariant}
                        onClick={handleConfirm}
                        disabled={loading}
                        className="w-full sm:w-auto"
                    >
                        {loading ? (
                            <>
                                <Loader2 className="h-4 w-4 animate-spin" />
                                {translate('main.loading') || 'Loading...'}
                            </>
                        ) : (
                            <>
                                {actionVariant === 'destructive' && <Trash2 className="h-4 w-4" />}
                                {actionText}
                            </>
                        )}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

// Usage examples:
// 
// Basic usage:
// <DeleteModal
//     open={isDeleteModalOpen}
//     onOpenChange={setIsDeleteModalOpen}
//     onConfirm={handleDelete}
//     title="Delete Company"
//     description="Are you sure you want to delete this company? This action cannot be undone."
// />
//
// Custom action button:
// <DeleteModal
//     open={isArchiveModalOpen}
//     onOpenChange={setIsArchiveModalOpen}
//     onConfirm={handleArchive}
//     title="Archive Item"
//     actionButtonText="Archive"
//     actionVariant="outline"
// />
//
// With custom content:
// <DeleteModal
//     open={isDeleteModalOpen}
//     onOpenChange={setIsDeleteModalOpen}
//     onConfirm={handleDelete}
//     title="Delete Multiple Items"
// >
//     <div className="space-y-3">
//         <p>You are about to delete the following items:</p>
//         <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground">
//             {selectedItems.map(item => (
//                 <li key={item.id}>{item.name}</li>
//             ))}
//         </ul>
//         <p className="text-destructive text-sm font-medium">
//             This action cannot be undone.
//         </p>
//     </div>
// </DeleteModal>
//
// With loading state:
// <DeleteModal
//     open={isDeleteModalOpen}
//     onOpenChange={setIsDeleteModalOpen}
//     onConfirm={handleDelete}
//     loading={isDeleting}
//     title="Delete User"
// />