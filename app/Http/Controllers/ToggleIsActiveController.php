<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class ToggleIsActiveController extends Controller
{
    /**
     * Handle the incoming request.
     */
    public function __invoke(Request $request)
    {
        $modelClass = $request->route('resource_model');
        $id = collect($request->route()->parameters())->first();

        $model = $modelClass::findOrFail($id);
        $model->update(['is_active' => !$model->is_active]);

        Log::info(__('flash.toggleSuccess'));
        Log::info(__('common.success'));

        return back()->with('success', __('flash.toggleSuccess'));
    }
}
