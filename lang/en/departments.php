<?php

return [
    'title' => 'Departments',
    'description' => 'Manage organizational departments and their structures',
    'addTitle' => 'Add Department',
    'departmentName' => 'Department Name',
    'searchPlaceholder' => 'Search by name or description',
    'emptyDescription' => 'Create a new department to get started.',
    'totalDepartments' => 'Total Departments',
    'activeDepartments' => 'Active Departments',
    'inactiveDepartments' => 'Inactive Departments',
    'activePercentage' => 'Active Percentage',
    'stats' => [
        'totalDescription' => 'All departments in system',
        'activeDescription' => 'Currently active departments',
        'inactiveDescription' => 'Currently inactive departments',
        'percentageDescription' => 'Of departments are active',
        'employeesCount' => 'Total Employees',
        'annualBudget' => 'Annual Budget',
        'createdDate' => 'Created',
        'status' => 'Status',
        'employeesCountDescription' => 'Including manager',
        'annualBudgetDescription' => 'Allocated budget',
        'statusDescription' => 'Current status',
    ],
    
    'empty' => [
        'title' => 'No Departments',
        'description' => 'Create your first department to get started',
    ],
    'modals' => [
        'create' => [
            'title' => 'Create Department',
            'description' => 'Add a new department to organize your organization structure.',
        ],
        'edit' => [
            'title' => 'Edit Department',
            'description' => 'Update the department details.',
        ],
        'view' => [
            'title' => 'Department Details',
        ],
    ],
    'pages' => [
        'create' => [
            'title' => 'Create Department',
            'description' => 'Add a new department to your organization',
        ],
        'edit' => [
            'title' => 'Edit Department',
            'description' => 'Update :departmentName information',
        ],
        'show' => [
            'title' => 'Department Details',
            'description' => 'View and manage department details',
            'manager_section' => 'Department Manager',
            'members_section' => 'Department Members',
        ],
    ],
    'flash' => [
        'created' => 'Department created successfully',
        'updated' => 'Department updated successfully',
        'deleted' => 'Department deleted successfully',
    ],
    'fields' => [
        'slug' => 'Slug',
        'createdAt' => 'Created At',
        'description' => 'Description',
        'manager' => 'Manager',
        'employees' => 'Employees',
        'budget' => 'Annual Budget',
    ],
    'form' => [
        'labels' => [
            'name' => 'Department Name',
            'description' => 'Description',
            'annual_budget' => 'Annual Budget',
            'manager_id' => 'Department Manager',
            'status' => 'Department Status',
        ],
        'descriptions' => [
            'status' => 'Enable or disable this department',
        ],
        'placeholder' => [
            'name' => 'Enter department name',
            'description' => 'Enter department description',
            'annual_budget' => '0.00',
        ],
        'actions' => [
            'cancel' => 'Cancel',
            'saving' => 'Saving...',
            'update' => 'Update Department',
            'create' => 'Create Department',
        ],
    ],
];