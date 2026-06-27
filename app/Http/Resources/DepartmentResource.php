<?php

namespace App\Http\Resources;

use App\Http\Resources\UserResource;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class DepartmentResource extends JsonResource
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
            'slug' => $this->slug,
            'description' => $this->description,
            'is_active' => $this->is_active,
            'annual_budget' => $this->annual_budget,
            'manager' => $this->whenLoaded('managerRelation', fn () => (new UserResource($this->managerRelation->first()))),
            'employees' => $this->whenLoaded('employees', fn() => UserResource::collection($this->employees)),
            'employees_count' => $this->whenLoaded('employees', function () {
                return $this->employees()->count();
            }),
            'my_role' => $this->when(isset($this->pivot), function () {
                return $this->pivot->role;
            }),
            'created_at' => $this->created_at?->format('Y-m-d'),
        ];
    }
}
