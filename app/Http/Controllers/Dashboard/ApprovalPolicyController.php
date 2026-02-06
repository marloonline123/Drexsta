<?php

namespace App\Http\Controllers\Dashboard;

use App\Http\Controllers\BaseController;
use App\Http\Requests\ApprovalPolicyRequest;
use App\Http\Resources\ApprovalPolicyResource;
use App\Models\Ability;
use App\Models\ApprovalPolicy;
use Illuminate\Http\Request;
use Inertia\Inertia;

class ApprovalPolicyController extends BaseController
{
    /**
     * Display a listing of the approval policies.
     */
    public function index()
    {
        // $this->authorize('viewAny', ApprovalPolicy::class);
        $policies = ApprovalPolicy::with('company')
            ->latest()
            ->get();

        $abilities = Ability::all();

        return Inertia::render('Dashboard/ApprovalPolicies/Index', [
            'policies' => ApprovalPolicyResource::collection($policies)->resolve(),
            'abilities' => $abilities,
        ]);
    }

    /**
     * Update the specified approval policy in storage.
     */
    public function update(ApprovalPolicyRequest $request, ApprovalPolicy $approvalPolicy)
    {
        $this->authorize('update', $approvalPolicy);
        $data = $request->validated();
        $approvalPolicy->update([
            'steps' => $data['steps'],
        ]);

        return redirect()->back()->with('success', 'Approval policy updated successfully.');
    }
}