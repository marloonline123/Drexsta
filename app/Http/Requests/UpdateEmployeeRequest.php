<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;

class UpdateEmployeeRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return Gate::allows('admin.employees.edit');
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        $employeeId = $this->route('employee') ? $this->route('employee')->id : null;
        return [
            'name' => 'required|string|max:255',
            'email' => 'required|email|max:255|unique:users,email,' . $employeeId,
            'phone' => 'nullable|string|max:255|unique:users,phone,' . $employeeId,
        ];
    }
}
