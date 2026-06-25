import { SidebarGroup, SidebarGroupLabel, SidebarMenu, SidebarMenuButton, SidebarMenuItem } from '@/Components/Ui/sidebar';
import { type NavItemsData, type Auth } from '@/Types';
import { Link, usePage } from '@inertiajs/react';
import { NAV_ITEMS_DATA } from '@/Const/NavItemsData';
import usePermissions from '@/Hooks/use-permissions';
import useTranslation from '@/Hooks/use-translation';


export function NavMain() {
    const page = usePage();
    const navItemsData: NavItemsData = NAV_ITEMS_DATA
    if (navItemsData.length === 0) return null;
    const { can } = usePermissions();
    const { translate } = useTranslation()


    return (
        <>
            {navItemsData.map((category) => (
                <SidebarGroup key={category.categoryName} className="px-2 py-0">
                    <SidebarGroupLabel>
                        {category.categoryIcon && <category.categoryIcon className="h-4 w-4" />}
                        {category.categoryName}
                    </SidebarGroupLabel>
                    <SidebarMenu>
                        {category.items
                            .filter((item) => !item.permission || can(item.permission))
                            .map((item) => (
                                <SidebarMenuItem key={item.title}>
                                    <SidebarMenuButton asChild isActive={page.url.startsWith(item.href)} tooltip={{ children: item.title }}>
                                        <Link href={item.href} prefetch preserveScroll>
                                            {item.icon && <item.icon />}
                                            <span>{translate(item.title)}</span>
                                        </Link>
                                    </SidebarMenuButton>
                                </SidebarMenuItem>
                            ))}
                    </SidebarMenu>
                </SidebarGroup>
            ))}
        </>
    );
}
