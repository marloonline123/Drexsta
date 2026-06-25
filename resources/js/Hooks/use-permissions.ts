import { PageProps } from '@/Types';
import { usePage } from '@inertiajs/react';

const usePermissions = () => {
    const {
        auth: { user },
    } = usePage<PageProps>().props;

    const can = (permission: string): boolean => {
        return user.permissions.find((p) => p.name === permission) ? true : false;
    };

    return { can }
};

export default usePermissions;
