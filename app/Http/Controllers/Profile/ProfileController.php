<?php

namespace App\Http\Controllers\Profile;

use App\Http\Controllers\Controller;
use App\Http\Requests\Settings\ProfileUpdateRequest;
use App\Http\Requests\UpdatePaymentMethodsRequest;
use App\Models\PaymentMethod;
use App\Models\UserPaymentData;
use App\Services\Shared\FileService;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia;
use Inertia\Response;

class ProfileController extends Controller
{
    protected FileService $fileService;

    public function __construct(FileService $fileService)
    {
        $this->fileService = $fileService;
    }

    /**
     * Show the user's profile settings page.
     */
    public function edit(Request $request): Response
    {
        $user = $request->user();
        $companyId = $user->active_company_id;

        $paymentMethods = PaymentMethod::where('company_id', $companyId)->active()->get();
        $userPaymentData = UserPaymentData::where('user_id', $user->id)
            ->with('paymentMethod')
            ->get();

        return Inertia::render('Profile/Info', [
            'mustVerifyEmail' => $request->user() instanceof MustVerifyEmail,
            'status' => $request->session()->get('status'),
            'paymentMethods' => $paymentMethods,
            'userPaymentData' => $userPaymentData,
        ]);
    }

    /**
     * Update the user's profile settings.
     */
    public function update(ProfileUpdateRequest $request): RedirectResponse
    {
        $user = Auth::user();
        
        // Handle profile photo upload
        if ($request->hasFile('profile_photo')) {
            $user->profile_photo_path = $this->fileService->storeImage(
                $request->file('profile_photo'), 
                'profile-photos'
            );
        }

        $user->fill($request->validated());

        if ($user->isDirty('email')) {
            $user->email_verified_at = null;
        }

        $user->save();

        return to_route('dashboard.profile.edit')->with('success', 'Profile updated successfully.');
    }

    /**
     * Show the payment data edit page.
     */
    public function editPaymentData(Request $request): Response
    {
        $user = $request->user();
        $companyId = $user->active_company_id;

        $paymentMethods = PaymentMethod::where('company_id', $companyId)->active()->get();
        $userPaymentData = UserPaymentData::where('user_id', $user->id)
            ->where('company_id', $companyId)
            ->with('paymentMethod')
            ->get();

        return Inertia::render('Profile/PaymentData', [
            'paymentMethods' => $paymentMethods,
            'userPaymentData' => $userPaymentData,
        ]);
    }

    /**
     * Update the user's payment data.
     */
    public function updatePaymentData(UpdatePaymentMethodsRequest $request): RedirectResponse
    {
        $user = Auth::user();
        $companyId = $user->active_company_id;
        $data = $request->validated();

        // Create new payment data if provided
        UserPaymentData::updateOrCreate([
            'user_id' => $user->id,
            'company_id' => $companyId,
        ], $data);

        return to_route('dashboard.profile.edit', ['tab' => 'payment-data'])->with('success', 'Payment methods updated successfully.');
    }

    /**
     * Delete the user's account.
     */
    public function destroy(Request $request): RedirectResponse
    {
        $request->validate([
            'password' => ['required', 'current_password'],
        ]);

        $user = $request->user();

        Auth::logout();

        $user->delete();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/');
    }
}