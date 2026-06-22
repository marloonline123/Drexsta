<?php

namespace App\Http\Controllers\Dashboard\Employee;

use App\Http\Controllers\BaseController;
use Illuminate\Http\Request;
use App\Exports\EmployeesExport;
use App\Imports\EmployeesImport;
use Maatwebsite\Excel\Facades\Excel;

class EmployeeExcelController extends BaseController
{

    /**
     * Export employees to Excel.
     */
    public function export()
    {
        $this->authorize('admin.employees.view');

        return Excel::download(new EmployeesExport, 'employees.xlsx');
    }

    /**
     * Import employees from Excel.
     */
    public function import(Request $request)
    {
        $this->authorize('admin.employees.create');

        $request->validate([
            'file' => 'required|mimes:xlsx,xls,csv',
        ]);

        Excel::import(new EmployeesImport, $request->file('file'));

        return back()->with('success', 'Employees imported successfully');
    }
}
