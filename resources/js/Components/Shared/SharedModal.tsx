import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/Components/Ui/dialog';
import { ReactNode } from 'react';

interface SharedModalProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    title: string | ReactNode;
    description: string | ReactNode;
    form: string | ReactNode;
}

export default function SharedModal({ open, onOpenChange, title, description, form }: SharedModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-[500px]">
                <DialogHeader>
                    <DialogTitle>{title}</DialogTitle>
                    <DialogDescription>
                        {description}
                    </DialogDescription>
                </DialogHeader>

                {/* Job Title Form */}
                {form}
            </DialogContent>
        </Dialog>
  )
}
