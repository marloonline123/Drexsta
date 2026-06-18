<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Facades\Storage;

class CompanyResource extends JsonResource
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
            'industry' => $this->industry,
            'slug' => $this->slug,
            'phone' => $this->phone,
            'email' => $this->email,
            'address' => $this->address,
            'description' => $this->description,
            'logo_url' => $this->logo_path
            ? Storage::disk(config('filesystems.default'))->url($this->logo_path)
            : null,
            'is_active' => $this->is_active,
            'employees_count' => $this->whenLoaded('employees', function () {
                return $this->employees->count();
            }),
            'myRole' => $this->whenLoaded('users', function () {
                return $this->users->firstWhere('id', request()->user()->id)?->pivot->role;
            }),
            'myJobTitles' => $this->whenLoaded('jobTitles', function () {
                return $this->jobTitles->map(fn($jobTitle) => [
                    'id' => $jobTitle->id,
                    'title' => $jobTitle->title,
                ]);
            }),
            'established_date' => $this->created_at?->format('Y-m-d'),
            'created_at' => $this->created_at,
        ];
    }
}
