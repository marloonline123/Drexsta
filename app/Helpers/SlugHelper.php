<?php

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

function generateSlug($string, $separator = '-')
{
    if (is_null($string) || $string === '') {
        return "";
    }

    $string = (string) $string;
    $string = trim($string);
    $string = mb_strtolower($string, "UTF-8");

    // Replace common punctuation and unsafe characters with separator
    $string = preg_replace('/[\/\\\\?#[\]@!$&\'()*+,;=.%^~`<>|"]/u', $separator, $string);

    // Keep all unicode letters, numbers, dashes, and spaces
    $string = preg_replace('/[^\p{L}\p{N}\s_-]+/u', '', $string);

    // Replace Arabic-specific variants (optional normalization)
    $string = str_replace(
        ['أ', 'إ', 'آ', 'ة', 'ء', 'ئ', 'ؤ'],
        ['ا', 'ا', 'ا', 'ه', 'ا', 'ى', 'و'],
        $string
    );

    // Replace multiple spaces/hyphens with a single space
    $string = preg_replace('/[\s\-]+/', ' ', $string);

    // Convert spaces/underscores to separator
    $string = preg_replace('/[\s_]/', $separator, $string);

    // Trim leading/trailing separators
    $string = trim($string, $separator);

    // Ensure result is not just separators
    if ($string === '' || preg_match("/^[" . preg_quote($separator, '/') . "]+$/", $string)) {
        return "";
    }

    return $string;
}

function generateUniqueSlug(string $model, string $title, ?int $ignoreId = null, string $column = 'slug'): string
{
    if (! class_exists($model) || ! is_subclass_of($model, Model::class)) {
        throw new InvalidArgumentException("Model {$model} does not exist.");
    }

    $baseSlug = $title === '' ? Str::random() : generateSlug($title);

    $existingSlugs = $model::where($column, 'LIKE', $baseSlug . '%')
        ->when($ignoreId, fn($q) => $q->whereKeyNot($ignoreId))
        ->pluck($column)
        ->unique();

    if ($existingSlugs->doesntContain($baseSlug)) {
        return $baseSlug;
    }

    $maxSuffix = 1;
    foreach ($existingSlugs as $existingSlug) {
        if (preg_match('/^' . preg_quote($baseSlug, '/') . '-([0-9]+)$/', $existingSlug, $matches)) {
            $maxSuffix = max($maxSuffix, (int)$matches[1]);
        }
    }

    return "{$baseSlug}-" . ($maxSuffix + 1);
}
