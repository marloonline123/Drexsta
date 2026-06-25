import { useCallback, useEffect } from 'react';
import { useForm, usePage } from '@inertiajs/react';

export function useLanguage() {
    const { props } = usePage();
    const { post } = useForm();
    
    const isRTL = props.locale === 'ar';
    const currentLanguage = props.locale || 'en';

    const changeLanguage = useCallback(async (lng: string) => {
        // Set document direction and language
        // document.documentElement.dir = lng === 'ar' ? 'rtl' : 'ltr';
        // document.documentElement.lang = lng;

        // // Update body classes for styling
        // document.body.classList.toggle('rtl', lng === 'ar');
        // document.body.classList.toggle('ltr', lng !== 'ar');

        // // Store in localStorage and cookie (cookie is read by server for SSR translations)
        // localStorage.setItem('language', lng);
        // document.cookie = `language=${lng};path=/;max-age=${365 * 24 * 60 * 60};SameSite=Lax`;

        // // Force a component update by refreshing the page
        // // This ensures all components re-render with new translations from server
        // setTimeout(() => {
        //     window.location.reload();
        // }, 100);
        post(route('locale.set', lng), {
            preserveScroll: true
        });
    }, []);

    // useEffect(() => {
    //     // Initialize direction and language on component mount
    //     const savedLanguage = localStorage.getItem('language') || 'en';

    //     document.documentElement.dir = savedLanguage === 'ar' ? 'rtl' : 'ltr';
    //     document.documentElement.lang = savedLanguage;
    //     document.body.classList.toggle('rtl', savedLanguage === 'ar');
    //     document.body.classList.toggle('ltr', savedLanguage !== 'ar');
    // }, []);

    return {
        isRTL,
        currentLanguage,
        changeLanguage,
    };
}
