<?php

return [
    'title' => 'المسميات الوظيفية',
    'description' => 'إدارة المسميات الوظيفية وتكويناتها',
    'addTitle' => 'إضافة مسمى وظيفي',
    'titleName' => 'اسم المسمى',
    'searchPlaceholder' => 'البحث بالعنوان أو الوصف',
    'emptyDescription' => 'أنشئ مسمى وظيفي جديد للبدء.',
    'totalJobTitles' => 'إجمالي المسميات الوظيفية',
    'activeJobTitles' => 'المسميات الوظيفية النشطة',
    'inactiveJobTitles' => 'المسميات الوظيفية غير النشطة',
    'activePercentage' => 'نسبة النشاط',
    'stats' => [
        'totalDescription' => 'جميع المسميات الوظيفية في النظام',
        'activeDescription' => 'المسميات الوظيفية النشطة حالياً',
        'inactiveDescription' => 'المسميات الوظيفية غير النشطة حالياً',
        'percentageDescription' => 'من المسميات الوظيفية نشطة',
    ],
    'headers' => [
        'title' => 'العنوان',
        'status' => 'الحالة',
        'date' => 'التاريخ',
        'actions' => 'الإجراءات',
    ],
    'actions' => [
        'view' => 'عرض',
        'edit' => 'تعديل',
        'delete' => 'حذف',
    ],
    'empty' => [
        'title' => 'لا توجد مسميات وظيفية',
        'description' => 'أنشئ أول مسمى وظيفي للبدء',
    ],
    'modals' => [
        'create' => [
            'title' => 'إنشاء مسمى وظيفي',
            'description' => 'أضف مسمى وظيفي جديد لتصنيف مناصب موظفيك.',
        ],
        'edit' => [
            'title' => 'تعديل المسمى الوظيفي',
            'description' => 'تحديث تفاصيل المسمى الوظيفي.',
        ],
        'form' => [
            'labels' => [
                'title' => 'اسم المسمى الوظيفي',
                'description' => 'الوصف',
                'status' => 'حالة المسمى الوظيفي',
            ],
            'descriptions' => [
                'status' => 'تمكين أو تعطيل هذا المسمى الوظيفي',
            ],
            'actions' => [
                'cancel' => 'إلغاء',
                'saving' => 'جارٍ الحفظ...',
                'update' => 'تحديث المسمى الوظيفي',
                'create' => 'إنشاء مسمى وظيفي',
            ],
        ],
    ],
];