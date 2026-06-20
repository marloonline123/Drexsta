import { useCallback, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { usePage } from '@inertiajs/react';

export function useLanguage() {
    const { i18n, t } = useTranslation();
    const { props } = usePage();
    const translation = (props as Record<string, unknown>).translation as Record<string, unknown> | undefined;

    const isRTL = i18n.language === 'ar';
    const currentLanguage = i18n.language;

    const changeLanguage = useCallback(async (lng: string) => {
        // Change i18n language
        await i18n.changeLanguage(lng);

        // Set document direction and language
        document.documentElement.dir = lng === 'ar' ? 'rtl' : 'ltr';
        document.documentElement.lang = lng;

        // Update body classes for styling
        document.body.classList.toggle('rtl', lng === 'ar');
        document.body.classList.toggle('ltr', lng !== 'ar');

        // Store in localStorage and cookie (cookie is read by server for SSR translations)
        localStorage.setItem('language', lng);
        document.cookie = `language=${lng};path=/;max-age=${365 * 24 * 60 * 60};SameSite=Lax`;

        // Force a component update by refreshing the page
        // This ensures all components re-render with new translations from server
        setTimeout(() => {
            window.location.reload();
        }, 100);
    }, [i18n]);

    useEffect(() => {
        // Sync server-provided translations into i18n
        if (translation && Object.keys(translation).length > 0) {
            i18n.addResourceBundle(currentLanguage, 'translation', translation, true, true);
        }

        // Initialize direction and language on component mount
        const savedLanguage = localStorage.getItem('language') || 'en';

        if (savedLanguage !== currentLanguage) {
            i18n.changeLanguage(savedLanguage);
        }

        document.documentElement.dir = savedLanguage === 'ar' ? 'rtl' : 'ltr';
        document.documentElement.lang = savedLanguage;
        document.body.classList.toggle('rtl', savedLanguage === 'ar');
        document.body.classList.toggle('ltr', savedLanguage !== 'ar');
    }, [currentLanguage, i18n, translation]);

    return {
        t,
        isRTL,
        currentLanguage,
        changeLanguage,
    };
}
