<?php

return [
    'title' => 'الأقسام',
    'description' => 'إدارة الأقسام التنظيمية وهياكلها',
    'addTitle' => 'إضافة قسم',
    'departmentName' => 'اسم القسم',
    'searchPlaceholder' => 'البحث بالاسم أو الوصف',
    'emptyDescription' => 'أنشئ قسمًا جديدًا للبدء.',
    'totalDepartments' => 'إجمالي الأقسام',
    'activeDepartments' => 'الأقسام النشطة',
    'inactiveDepartments' => 'الأقسام غير النشطة',
    'activePercentage' => 'نسبة النشاط',
    'empty' => [
        'title' => 'لا توجد أقسام',
        'description' => 'أنشئ أول قسم للبدء',
    ],
    'flash' => [
        'created' => 'تم إنشاء القسم بنجاح',
        'updated' => 'تم تحديث القسم بنجاح',
        'deleted' => 'تم حذف القسم بنجاح',
    ],
    'fields' => [
        'slug' => 'الاسم المعرف',
        'createdAt' => 'تاريخ الإنشاء',
        'description' => 'الوصف',
        'manager' => 'المدير',
        'employees' => 'الموظفين',
        'budget' => 'الميزانية السنوية',
    ],
    'modals' => [
        'create' => [
            'title' => 'إنشاء قسم',
            'description' => 'أضف قسمًا جديدًا لتنظيم هيكل مؤسستك.',
        ],
        'edit' => [
            'title' => 'تعديل القسم',
            'description' => 'تحديث تفاصيل القسم.',
        ],
        'view' => [
            'title' => 'تفاصيل القسم',
        ],
    ],
    'pages' => [
        'create' => [
            'title' => 'إنشاء قسم',
            'description' => 'أضف قسمًا جديدًا لمؤسستك',
        ],
        'edit' => [
            'title' => 'تعديل القسم',
            'description' => 'تحديث معلومات القسم',
        ],
        'show' => [
            'title' => 'تفاصيل القسم',
            'description' => 'ادارة تفاصيل القسم',
            'manager_section' => 'مدير القسم',
            'members_section' => 'أعضاء القسم',
        ],
    ],
    'stats' => [
        'totalDescription' => 'إجمالي الأقسام في النظام',
        'activeDescription' => 'الأقسام النشطة حاليًا',
        'inactiveDescription' => 'الأقسام غير النشطة حاليًا',
        'percentageDescription' => 'نسبة الأقسام النشطة',
        'employeesCount' => 'إجمالي الموظفين',
        'annualBudget' => 'الميزانية السنوية',
        'createdDate' => 'تاريخ الإنشاء',
        'status' => 'الحالة',
        'employeesCountDescription' => 'بما في ذلك المدير',
        'annualBudgetDescription' => 'الميزانية المخصصة',
        'statusDescription' => 'الحالة الحالية',
    ],
    'form' => [
        'labels' => [
            'name' => 'اسم القسم',
            'description' => 'الوصف',
            'annual_budget' => 'الميزانية السنوية',
            'manager_id' => 'مدير القسم',
            'status' => 'حالة القسم',
        ],
        'placeholder' => [
            'name' => 'أدخل اسم القسم',
            'description' => 'أدخل وصف القسم',
            'annual_budget' => '0.00',
        ],
        'descriptions' => [
            'status' => 'تمكين أو تعطيل هذا القسم',
        ],
        'actions' => [
            'cancel' => 'إلغاء',
            'saving' => 'جارٍ الحفظ...',
            'update' => 'تحديث القسم',
            'create' => 'إنشاء قسم',
        ],
    ],
];