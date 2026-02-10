<?php

namespace App\Http\Controllers\Dashboard;

use App\Http\Controllers\BaseController;
use App\Http\Requests\RoleRequest;
use App\Http\Resources\RoleResource;
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia;
use App\Models\Role;
use App\Models\Permission;

class RolesController extends BaseController
{
    /**
     * Display the roles management page.
     */
    public function index()
    {
        $this->authorize('viewAny', Role::class);
        $roles = Role::with('permissions', 'users')
            ->search(request('search'), 'name')
            ->paginate(12)
            ->withQueryString();

        $rolesCollection = RoleResource::collection($roles);

        // Also fetch permissions for the frontend
        $permissions = Permission::all();

        return Inertia::render('Dashboard/Roles/Index', [
            'roles' => $rolesCollection,
            'permissions' => $this->groupPermissions($permissions),
        ]);
    }

    /**
     * Store a newly created role.
     */
    public function store(RoleRequest $request)
    {
        $this->authorize('create', Role::class);
        $data = $request->validated();
        $user = Auth::user();

        $role = Role::create([
            'name' => $data['name'],
            'company_id' => $user->active_company_id,
        ]);

        if (isset($data['permissions'])) {
            $role->syncPermissions($data['permissions'], $user->active_company_id);
        }

        return back()->with('success', 'Role created successfully');
    }

    /**
     * Update the specified role.
     */
    public function update(RoleRequest $request, Role $role)
    {
        $this->authorize('update', $role);
        $data = $request->validated();
        $user = Auth::user();

        $role->update($data);

        if (isset($data['permissions'])) {
            $role->syncPermissions($data['permissions'], $user->active_company_id);
        }

        return back()->with('success', 'Role updated successfully');
    }

    /**
     * Remove the specified role.
     */
    public function destroy(Role $role)
    {
        $this->authorize('delete', $role);
        $role->delete();

        return back()->with('success', 'Role deleted successfully');
    }

    /**
     * Get all available permissions for the current company.
     */
    public function permissions()
    {
        $permissions = Permission::all();

        return response()->json([
            'permissions' => $this->groupPermissions($permissions),
        ]);
    }

    /**
     * Group permissions by category (e.g. users.view → category 'users').
     */
    private function groupPermissions($permissions): array
    {
        $grouped = [];
        foreach ($permissions as $permission) {
            $parts = explode('.', $permission->name);
            $category = $parts[0] ?? 'general';
            $action = $parts[1] ?? $permission->name;

            if (!isset($grouped[$category])) {
                $grouped[$category] = [];
            }

            $grouped[$category][] = [
                'id' => $permission->id,
                'name' => $permission->name,
                'category' => $category,
                'action' => $action,
            ];
        }

        return $grouped;
    }
}