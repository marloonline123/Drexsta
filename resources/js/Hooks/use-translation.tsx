import { PageProps } from '@/Types';
import { usePage } from '@inertiajs/react';

export default function useTranslation() {
    const translations = usePage<PageProps>().props.translations;

    const translate = (key: string): string => {
        // Handle nested keys like 'admin.jobTitles.title'
        if (!translations) return key;
        
        const keys = key.split('.');
        let result: any = translations;
        
        for (const k of keys) {
            if (result && typeof result === 'object' && k in result) {
                result = result[k];
            } else {
                return key;
            }
        }
        
        return typeof result === 'string' ? result : key;
    };

    return {
        translate,
    };
}
