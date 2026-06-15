<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Facades\Storage;

class UserResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'username' => $this->username,
            'email' => $this->email,
            'phone' => $this->phone,
            'profile_photo_url' => $this->profile_photo_path
                ? Storage::disk(config('filesystems.default'))->url($this->profile_photo_path)
                : null,
            'department_role' => $this->when(
                isset($this->pivot),
                fn() => $this->pivot->role
            ),
            'activeCompany' => $this->whenLoaded('activeCompany', new CompanyResource($this->activeCompany)),
            'roles' => $this->whenLoaded('roles', RoleResource::collection($this->roles)),
            'permissions' => $this->whenLoaded('permissions', PermissionResource::collection($this->getAllPermissions())),
            'permissions' => PermissionResource::collection($this->getAllPermissions()),
            'joined_at' => $this->created_at?->format('Y-m-d'),
        ];
    }
}
