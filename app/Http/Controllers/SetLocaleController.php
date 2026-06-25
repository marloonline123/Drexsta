<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class SetLocaleController extends Controller
{
    /**
     * Handle the incoming request.
     */
    public function __invoke(string $locale)
    {
        $data = ['locale' => $locale];
        // Validator::validate($data, ['locale' => 'string|in:en,ar']);

        session($data);

        return back();
    }
}
