<?php

return [
    'title' => 'أنواع التوظيف',
    'description' => 'إدارة أنواع التوظيف المختلفة وتكويناتها',
    'addType' => 'إضافة نوع توظيف',
    'typeName' => 'اسم النوع',
    'hoursPerWeek' => 'ساعات في الأسبوع',
    'benefits' => 'المزايا',
    'included' => 'مشمولة',
    'notIncluded' => 'غير مشمولة',
    'searchPlaceholder' => 'البحث بالاسم أو الوصف',
    'emptyDescription' => 'أنشئ نوع توظيف جديد للبدء.',
    'totalEmploymentTypes' => 'إجمالي أنواع التوظيف',
    'activeEmploymentTypes' => 'أنواع التوظيف النشطة',
    'inactiveEmploymentTypes' => 'أنواع التوظيف غير النشطة',
    'activePercentage' => 'نسبة النشاط',
    'stats' => [
        'totalDescription' => 'جميع أنواع التوظيف في النظام',
        'activeDescription' => 'أنواع التوظيف النشطة حاليًا',
        'inactiveDescription' => 'أنواع التوظيف غير النشطة حاليًا',
        'percentageDescription' => 'من أنواع التوظيف نشطة',
    ],
    
    'empty' => [
        'title' => 'لا توجد أنواع توظيف',
        'description' => 'أنشئ أول نوع توظيف للبدء',
    ],
    'fields' => [
        'slug' => 'الاسم المعرف',
        'createdAt' => 'تاريخ الانشاء',
        'description' => 'الوصف',
        'company' => 'الشركة',
    ],
    'modals' => [
        'create' => [
            'title' => 'إنشاء نوع توظيف',
            'description' => 'أضف نوع توظيف جديد لتصنيف عقود موظفيك.',
        ],
        'edit' => [
            'title' => 'تعديل نوع التوظيف',
            'description' => 'تحديث معلومات نوع التوظيف.',
        ],
        'view' => [
            'title' => 'تفاصيل نوع التوظيف',
        ],
    ],
    'form' => [
        'labels' => [
            'title' => 'اسم نوع التوظيف',
            'description' => 'الوصف',
            'status' => 'حالة نوع التوظيف',
        ],
        'placeholder' => [
            'title' => 'ادخل اسم نوع التوظيف',
            'description' => 'ادخل وصف نوع التوظيف' 
        ],
        'descriptions' => [
            'status' => 'تمكين أو تعطيل هذا النوع التوظيفي',
        ],
        'actions' => [
            'cancel' => 'إلغاء',
            'saving' => 'جارٍ الحفظ...',
            'update' => 'تحديث نوع التوظيف',
            'create' => 'إنشاء نوع توظيف',
        ],
    ],
];