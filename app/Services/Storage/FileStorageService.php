<?php

namespace App\Services\Storage;

use Exception;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;

class FileStorageService
{
    public function __construct(
        protected $file,
        protected string $path,
        protected ?string $disk = null,
        protected $media = null,
        protected $processor = null,
        protected $finalFile = null,
    ) {
        $this->file = $file;
        $this->finalFile = $file;
        $this->path = $path;
        $this->disk = config('filesystems.default', 'public');
    }

    public function disk(string $disk): self
    {
        $this->disk = $disk;
        return $this;
    }

    protected function resolveProcessor()
    {
        $mime = mime_content_type($this->file);

        if (str_starts_with($mime, 'image/')) {
            // return new ImageProcessor($this->file);
        }

        if (str_starts_with($mime, 'video/')) {
            // return new VideoProcessor($this->file);
        }

        return null;
    }

    public function crop(int $width, int $height): self
    {
        $this->finalFile = $this->processor->cover($this->media, $width, $height);
        return $this;
    }

    public function resize(int $width, int $height): self
    {
        $this->finalFile = $this->processor->resize($this->media, $width, $height);
        return $this;
    }

    public function save(): string
    {
        $content = $this->processor
            ? $this->processor->getEncoded()
            : file_get_contents($this->finalFile);

        Storage::disk($this->disk)->put($this->path, $content);

        return $this->path;
    }

    /**
     * Store an uploaded image and return its storage path.
     */
    public function storeImage(UploadedFile $image, string $directory = 'images/others', ?string $customName = null): string
    {
        try {
            // Ensure the directory has no trailing slash
            $directory = rtrim($directory, '/');

            // Generate a filename (custom or original)
            $filename = $customName
                ? $customName . '.' . $image->extension()
                : $image->hashName();

            // Ensure uniqueness
            $filename = $this->ensureUniqueFilename($directory, $filename);

            // Store the file
            return $image->storeAs($directory, $filename, $this->disk);
        } catch (Exception $e) {
            throw new Exception("Image upload failed: " . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Store an uploaded image and return its storage path.
     */
    public function storeFile(UploadedFile $file, int $companyId, string $directory = 'files/others', ?string $customName = null): string
    {
        try {
            // Ensure the directory has no trailing slash
            $directory = 'COMPANYID_' . $companyId . '/' . rtrim($directory, '/');

            // Generate a filename (custom or original)
            $filename = $customName
                ? $customName . '.' . $file->extension()
                : $file->hashName();

            // Ensure uniqueness
            $filename = $this->ensureUniqueFilename($directory, $filename);

            // Store the file
            return $file->storeAs($directory, $filename, $this->disk);
        } catch (Exception $e) {
            throw new Exception("Image upload failed: " . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Delete a file from storage.
     */
    public function deleteFile(string $filePath): bool
    {
        try {
            if (Storage::disk($this->disk)->exists($filePath)) {
                return Storage::disk($this->disk)->delete($filePath);
            }
            return false;
        } catch (Exception $e) {
            throw new Exception("File deletion failed: " . $e->getMessage(), 0, $e);
        }
    }

    protected function ensureUniqueFilename(string $directory, string $filename, int $attempt = 0): string
    {
        $disk = Storage::disk($this->disk);

        // Split filename into name + extension
        $name = pathinfo($filename, PATHINFO_FILENAME);
        $extension = pathinfo($filename, PATHINFO_EXTENSION);

        // Append suffix if not first attempt
        $candidate = $attempt > 0
            ? "{$name}_{$attempt}." . $extension
            : $filename;

        // Full path for existence check
        $path = $directory . '/' . $candidate;

        // If exists → recurse with incremented attempt
        if ($disk->exists($path)) {
            return $this->ensureUniqueFilename($directory, $filename, $attempt + 1);
        }

        return $candidate;
    }
}
