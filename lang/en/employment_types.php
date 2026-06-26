<?php

return [
    'title' => 'Employment Types',
    'description' => 'Manage different employment types and their configurations',
    'addType' => 'Add Employment Type',
    'typeName' => 'Type Name',
    'hoursPerWeek' => 'Hours per Week',
    'benefits' => 'Benefits',
    'included' => 'Included',
    'notIncluded' => 'Not Included',
    'searchPlaceholder' => 'Search by name or description',
    'emptyDescription' => 'Create a new employment type to get started.',
    'totalEmploymentTypes' => 'Total Employment Types',
    'activeEmploymentTypes' => 'Active Employment Types',
    'inactiveEmploymentTypes' => 'Inactive Employment Types',
    'activePercentage' => 'Active Percentage',
    'stats' => [
        'totalDescription' => 'All employment types in system',
        'activeDescription' => 'Currently active employment types',
        'inactiveDescription' => 'Currently inactive employment types',
        'percentageDescription' => 'Of employment types are active',
    ],
    
    'empty' => [
        'title' => 'No Employment Types',
        'description' => 'Create your first employment type to get started',
    ],
    'modals' => [
        'create' => [
            'title' => 'Create Employment Type',
            'description' => 'Add a new employment type to categorize your employee positions.',
        ],
        'edit' => [
            'title' => 'Edit Employment Type',
            'description' => 'Update the employment type details.',
        ],
        'view' => [
            'title' => 'Employment Type Details',
        ],
    ],
    'fields' => [
        'slug' => 'Slug',
        'createdAt' => 'Created At',
        'description' => 'Description',
        'company' => 'Company',
    ],
    'form' => [
        'labels' => [
            'title' => 'Employment Type Name',
            'description' => 'Description',
            'status' => 'Employment Type Status',
        ],
        'descriptions' => [
            'status' => 'Enable or disable this employment type',
        ],
        'placeholder' => [
            'title' => 'Enter employment type name',
            'description' => 'Enter employment type description',
        ],
        'actions' => [
            'cancel' => 'Cancel',
            'saving' => 'Saving...',
            'update' => 'Update Employment Type',
            'create' => 'Create Employment Type',
        ],
    ],
];