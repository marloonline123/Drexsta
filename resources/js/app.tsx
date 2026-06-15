import '../css/app.css';
import './Lib/i18n';

import { createInertiaApp } from '@inertiajs/react';
import { resolvePageComponent } from 'laravel-vite-plugin/inertia-helpers';
import { createRoot } from 'react-dom/client';
import { initializeTheme } from './Hooks/use-appearance';

const appName = import.meta.env.VITE_APP_NAME || 'Laravel';

createInertiaApp({
    title: (title) => title ? `${title} - ${appName}` : appName,
    resolve: (name) => {
        const defaultPages = import.meta.glob('./Pages/**/*.{js,jsx,ts,tsx}');
        const modulePages = import.meta.glob('../../modules/**/Ui/Resources/Inertia/Pages/**/*.{js,jsx,ts,tsx}');

        for (const ext of ['.jsx', '.tsx', '.js', '.ts']) {
            const defaultPath = `./Pages/${name}${ext}`;
            if (defaultPages[defaultPath]) {
                return defaultPages[defaultPath]();
            }
        }

        const parts = name.split('/');
        const moduleName = parts.length > 1 ? parts[0] : name;
        const pageName = parts.length > 1 ? parts.slice(1).join('/') : 'Index';

        for (const path in modulePages) {
            for (const ext of ['.jsx', '.tsx', '.js', '.ts']) {
                const expectedSuffix = `${moduleName}/Ui/Resources/Inertia/Pages/${pageName}${ext}`;
                if (path.toLowerCase().endsWith(expectedSuffix.toLowerCase())) {
                    return modulePages[path]();
                }
            }
        }

        throw new Error(`Page component not found: ${name}`);
    },
    setup({ el, App, props }) {
        const root = createRoot(el);

        root.render(<App {...props} />);
    },
    progress: {
        color: '#4B5563',
    },
});

// This will set light / dark mode on load...
initializeTheme();
