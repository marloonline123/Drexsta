import { User } from "@/Types/user";
import {
    Users, Crown, Building, Clock, Calculator, FileText, Settings, Shield,
    Calendar, Briefcase, ClipboardList, ClipboardCheck,
    FilePlus2, FileCheck2, Layers, CheckSquare,
    CalendarDays, Network
} from "lucide-react";

export const getPermissionCategoryIcon = (category: string) => {
    const icons = {
        users: Users,
        roles: Crown,
        companies: Building,
        employees: Users,
        attendance: Clock,
        payroll: Calculator,
        reports: FileText,
        leaves: Calendar,              // leave requests → calendar
        abilities: CheckSquare,        // skills/abilities → checklist
        holidays: CalendarDays,        // holidays → marked calendar
        "job-titles": Briefcase,       // job titles → briefcase
        "job-requisitions": ClipboardList, // requisitions → list
        "job-postings": FilePlus2,     // postings → new file/post
        "employment-types": Layers,    // types → stacked layers
        "approval-policies": FileCheck2, // approvals → checked file
        "leave-types": ClipboardCheck, // leave types → check clipboard
        departments: Network,          // org departments → network
        settings: Settings,
    };
    const Icon = icons[category as keyof typeof icons] || Shield;
    return <Icon className="h-4 w-4" />;
};