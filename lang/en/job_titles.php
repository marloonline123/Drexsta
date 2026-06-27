<?php

return [
    'title' => 'Job Titles',
    'description' => 'Manage job titles and their configurations',
    'addTitle' => 'Add Job Title',
    'titleName' => 'Title Name',
    'searchPlaceholder' => 'Search by title or description',
    'emptyDescription' => 'Create a new job title to get started.',
    'totalJobTitles' => 'Total Job Titles',
    'activeJobTitles' => 'Active Job Titles',
    'inactiveJobTitles' => 'Inactive Job Titles',
    'activePercentage' => 'Active Percentage',
    'stats' => [
        'totalDescription' => 'All job titles in system',
        'activeDescription' => 'Currently active job titles',
        'inactiveDescription' => 'Currently inactive job titles',
        'percentageDescription' => 'Of job titles are active',
    ],
    
    'empty' => [
        'title' => 'No Job Titles',
        'description' => 'Create your first job title to get started',
    ],
    'modals' => [
        'create' => [
            'title' => 'Create Job Title',
            'description' => 'Add a new job title to categorize your employee positions.',
        ],
        'edit' => [
            'title' => 'Edit Job Title',
            'description' => 'Update the job title details.',
        ],
        'view' => [
            'title' => 'Job Title Details',
        ],
    ],
    'flash' => [
        'created' => 'Job title created successfully',
        'updated' => 'Job title updated successfully',
        'deleted' => 'Job title deleted successfully',
    ],
    'fields' => [
        'slug' => 'Slug',
        'createdAt' => 'Created At',
        'description' => 'Description',
        'company' => 'Company',
    ],
    'form' => [
        'labels' => [
            'title' => 'Job Title Name',
            'description' => 'Description',
            'status' => 'Job Title Status',
        ],
        'descriptions' => [
            'status' => 'Enable or disable this job title',
        ],
        'placeholder' => [
            'title' => 'ادخل المسمى الوظيفي',
            'description' => 'ادخل وصف المسمى الوظيفي' 
        ],
        'actions' => [
            'cancel' => 'Cancel',
            'saving' => 'Saving...',
            'update' => 'Update Job Title',
            'create' => 'Create Job Title',
        ],
    ],
];