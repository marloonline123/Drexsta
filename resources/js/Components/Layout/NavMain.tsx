import { SidebarGroup, SidebarGroupLabel, SidebarMenu, SidebarMenuButton, SidebarMenuItem } from '@/Components/Ui/sidebar';
import { type NavItemsData, type Auth } from '@/Types';
import { Link, usePage } from '@inertiajs/react';
import { hasPermissionTo } from '@/Lib/permissions';
import { NAV_ITEMS_DATA } from '@/Const/NavItemsData';


export function NavMain() {
    const page = usePage();
    const { user } = page.props.auth as Auth;
    const navItemsData: NavItemsData = NAV_ITEMS_DATA
    if (navItemsData.length === 0) return null;

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
                            .filter((item) => !item.permission || hasPermissionTo(user, item.permission))
                            .map((item) => (
                                <SidebarMenuItem key={item.title}>
                                    <SidebarMenuButton asChild isActive={page.url.startsWith(item.href)} tooltip={{ children: item.title }}>
                                        <Link href={item.href} prefetch preserveScroll>
                                            {item.icon && <item.icon />}
                                            <span>{item.title}</span>
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
