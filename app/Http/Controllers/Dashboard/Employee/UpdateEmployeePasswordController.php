<?php

namespace App\Http\Controllers\Dashboard\Employee;

use App\Http\Controllers\BaseController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules\Password;
use App\Models\User;

class UpdateEmployeePasswordController extends BaseController
{
    /**
     * handle the form for updating the password.
     */
    public function updatePassword(Request $request, User $employee)
    {
        $this->authorize('admin.employees.edit');

        $validated = $request->validate([
            'password' => ['required', Password::defaults(), 'confirmed'],
        ]);

        $employee->update([
            'password' => Hash::make($validated['password']),
        ]);

        return back()->with('success', 'Password updated successfully');
    }
}
