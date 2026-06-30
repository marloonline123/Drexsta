<?php

namespace App\Http\Controllers\Dashboard;

use App\Http\Controllers\BaseController;
use App\Http\Requests\PaymentMethodRequest;
use App\Models\PaymentMethod;
use Illuminate\Http\Request;
use Inertia\Inertia;

class PaymentMethodController extends BaseController
{
    /**
     * Display a listing of the payment methods.
     */
    public function index()
    {
        $this->authorize('viewAny', PaymentMethod::class);

        $paymentMethods = PaymentMethod::latest()
            ->paginate(10);

        return Inertia::render('Dashboard/PaymentMethods/Index', [
            'paymentMethods' => $paymentMethods,
        ]);
    }

    /**
     * Show the form for creating a new payment method.
     */
    public function create()
    {
        $this->authorize('create', PaymentMethod::class);

        return Inertia::render('Dashboard/PaymentMethods/Create');
    }

    /**
     * Store a newly created payment method in storage.
     */
    public function store(PaymentMethodRequest $request)
    {
        $this->authorize('create', PaymentMethod::class);
        $data = $request->validated();
        PaymentMethod::create($data + [
            'company_id' => request()->user()->active_company_id,
            'slug' => generateUniqueSlug(PaymentMethod::class, $request->input('name')),
        ]);

        return redirect()->route('dashboard.payment-methods.index')
            ->with('success', 'Payment method created successfully.');
    }

    /**
     * Display the specified payment method.
     */
    public function show(PaymentMethod $paymentMethod)
    {
        $this->authorize('view', $paymentMethod);

        return Inertia::render('Dashboard/PaymentMethods/Show', [
            'paymentMethod' => $paymentMethod,
        ]);
    }

    /**
     * Show the form for editing the specified payment method.
     */
    public function edit(PaymentMethod $paymentMethod)
    {
        $this->authorize('update', $paymentMethod);

        return Inertia::render('Dashboard/PaymentMethods/Edit', [
            'paymentMethod' => $paymentMethod,
        ]);
    }

    /**
     * Update the specified payment method in storage.
     */
    public function update(PaymentMethodRequest $request, PaymentMethod $paymentMethod)
    {
        $this->authorize('update', $paymentMethod);

        $paymentMethod->fill($request->validated());

        if ($paymentMethod->isDirty('name')) {
            $paymentMethod->slug = uniqueSlug(PaymentMethod::class, $request->input('name'));
        }

        $paymentMethod->save();

        return redirect()->route('dashboard.payment-methods.index')
            ->with('success', 'Payment method updated successfully.');
    }

    /**
     * Remove the specified payment method from storage.
     */
    public function destroy(PaymentMethod $paymentMethod)
    {
        $this->authorize('delete', $paymentMethod);

        $paymentMethod->delete();

        return redirect()->route('dashboard.payment-methods.index')
            ->with('success', 'Payment method deleted successfully.');
    }
}
