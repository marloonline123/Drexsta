import { useCallback, useEffect, useState } from 'react';

export type Theme = 'light' | 'dark' | 'system';

const prefersDark = () => {
    if (typeof window === 'undefined') {
        return false;
    }

    return window.matchMedia('(prefers-color-scheme: dark)').matches;
};

const setCookie = (name: string, value: string, days = 365) => {
    if (typeof document === 'undefined') {
        return;
    }

    const maxAge = days * 24 * 60 * 60;
    document.cookie = `${name}=${value};path=/;max-age=${maxAge};SameSite=Lax`;
};

const applyTheme = (theme: Theme) => {
    const isDark = theme === 'dark' || (theme === 'system' && prefersDark());

    document.documentElement.classList.toggle('dark', isDark);
};

const mediaQuery = () => {
    if (typeof window === 'undefined') {
        return null;
    }

    return window.matchMedia('(prefers-color-scheme: dark)');
};

const handleSystemThemeChange = () => {
    const currentTheme = localStorage.getItem('theme') as Theme;
    applyTheme(currentTheme || 'system');
};

export function initializeTheme() {
    const savedTheme = (localStorage.getItem('theme') as Theme) || 'system';

    applyTheme(savedTheme);

    // Add the event listener for system theme changes...
    mediaQuery()?.addEventListener('change', handleSystemThemeChange);
}

export function useAppearance() {
    const [theme, setThemeState] = useState<Theme>('system');

    const setTheme = useCallback((mode: Theme) => {
        setThemeState(mode);

        // Store in localStorage for client-side persistence...
        localStorage.setItem('theme', mode);

        // Store in cookie for SSR...
        setCookie('theme', mode);

        applyTheme(mode);
    }, []);

    useEffect(() => {
        const savedTheme = localStorage.getItem('theme') as Theme | null;
        setTheme(savedTheme || 'system');

        return () => mediaQuery()?.removeEventListener('change', handleSystemThemeChange);
    }, [setTheme]);

    return { theme, setTheme } as const;
}
