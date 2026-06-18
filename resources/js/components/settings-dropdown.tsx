import { Button } from '@/Components/Ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/Components/Ui/dropdown-menu';
import { useAppearance } from '@/Hooks/use-appearance';
import { useLanguage } from '@/Hooks/use-language';
import { Monitor, Moon, Sun, Globe, Settings } from 'lucide-react';
import { HTMLAttributes } from 'react';

export default function SettingsDropdown({ className = '', ...props }: HTMLAttributes<HTMLDivElement>) {
    const { theme, setTheme } = useAppearance();
    const { currentLanguage, changeLanguage, t } = useLanguage();

    const languages = [
        { code: 'en', name: 'English', flag: '🇺🇸' },
        { code: 'ar', name: 'العربية', flag: '🇸🇦' },
    ];

    const themeOptions = [
        { value: 'light', label: t('settings.light'), icon: Sun },
        { value: 'dark', label: t('settings.dark'), icon: Moon },
        { value: 'system', label: t('settings.system'), icon: Monitor }
    ];

    const currentLang = languages.find(lang => lang.code === currentLanguage);
    const currentTheme = themeOptions.find(t => t.value === theme);

    return (
        <div className={className} {...props}>
            <DropdownMenu>
                <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon" className="h-9 w-9 rounded-md">
                        <Settings className="h-5 w-5" />
                        <span className="sr-only">Settings</span>
                    </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                    <DropdownMenuLabel>{t('settings.appearance')}</DropdownMenuLabel>
                    {themeOptions.map((themeOption) => {
                        const Icon = themeOption.icon;
                        return (
                            <DropdownMenuItem 
                                key={themeOption.value}
                                onClick={() => setTheme(themeOption.value as 'light' | 'dark' | 'system')}
                                className={theme === themeOption.value ? 'bg-accent' : ''}
                            >
                                <span className="flex items-center gap-2">
                                    <Icon className="h-4 w-4" />
                                    {themeOption.label}
                                    {theme === themeOption.value && (
                                        <span className="ml-auto text-xs text-primary">✓</span>
                                    )}
                                </span>
                            </DropdownMenuItem>
                        );
                    })}
                    
                    <DropdownMenuSeparator />
                    
                    <DropdownMenuLabel>{t('settings.language')}</DropdownMenuLabel>
                    {languages.map((language) => (
                        <DropdownMenuItem 
                            key={language.code}
                            onClick={() => changeLanguage(language.code)}
                            className={currentLanguage === language.code ? 'bg-accent' : ''}
                        >
                            <span className="flex items-center gap-2">
                                <span>{language.flag}</span>
                                {language.name}
                                {currentLanguage === language.code && (
                                    <span className="ml-auto text-xs text-primary">✓</span>
                                )}
                            </span>
                        </DropdownMenuItem>
                    ))}
                </DropdownMenuContent>
            </DropdownMenu>
        </div>
    );
}