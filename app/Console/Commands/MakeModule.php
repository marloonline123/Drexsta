<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;

class MakeModule extends Command
{
    protected $signature = 'make:module {module} {--context=Core}';
    protected $description = 'Create a full module skeleton automatically using stubs';

    public function handle()
    {
        $module = ucfirst($this->argument('module'));
        $lowerModule = strtolower($module);
        $context = ucfirst($this->option('context'));
        $tableName = Str::plural(Str::snake($module));

        $stubs = [
            'module.json.stub' => "module.json",
            'provider.stub' => "{$module}ServiceProvider.php",
            'controller.stub' => "Ui/Http/Controllers/{$module}Controller.php",
            'routes.stub' => "Ui/Routes/{$lowerModule}.php",
            'request.stub' => "Ui/Http/Requests/Create{$module}Request.php",
            'domain.stub' => "Domain/{$module}.php",
            'service_contract.stub' => "Domain/Contracts/{$module}Service.php",
            'model.stub' => "Infrastructure/Persistence/Eloquent{$module}Model.php",
            'service.stub' => "Infrastructure/Services/Laravel{$module}Service.php",
            'usecase.stub' => [
                "Application/Usecases/Create{$module}.php",
                "Application/Usecases/Update{$module}.php",
                "Application/Usecases/Delete{$module}.php",
                "Application/Usecases/Get{$module}.php",
                "Application/Usecases/List" . Str::plural($module) . ".php",
            ],
            'inertia.stub' => "Ui/Resources/Inertia/Pages/Index.jsx",
            'blade.stub' => "Ui/Resources/Blade/Views/index.blade.php",
            'migration.stub' => "Database/Migrations/" . date('Y_m_d_His') . "_create_{$tableName}_table.php",
        ];

        $targetBasePath = base_path("modules/{$context}/{$module}");

        if (File::exists($targetBasePath)) {
            $this->error("Module {$module} already exists!");
            return;
        }

        foreach ($stubs as $stubFile => $targetFiles) {
            $stubPath = base_path("stubs/module/{$stubFile}");

            if (!File::exists($stubPath)) {
                $this->warn("Stub not found: {$stubPath}");
                continue;
            }

            $stubContent = File::get($stubPath);

            $replacements = [
                '{{MODULE}}' => $module,
                '{{BASE_NAME}}' => $module,
                '{{LOWER_MODULE}}' => $lowerModule,
                '{{CONTEXT}}' => $context,
                '{{TABLE_NAME}}' => $tableName,
            ];

            foreach ((array)$targetFiles as $targetFileName) {
                $baseName = pathinfo($targetFileName, PATHINFO_FILENAME);
                $className = preg_replace('/^\d{4}_\d{2}_\d{2}_\d{6}_/', '', $baseName); // Strip migration timestamp for class naming

                $dirName = dirname($targetFileName);
                $namespacePath = str_replace('/', '\\', $dirName);
                if ($namespacePath === '.') {
                    $namespace = "Modules\\{$context}\\{$module}";
                }
                else {
                    $namespace = "Modules\\{$context}\\{$module}\\{$namespacePath}";
                }

                $replacements['{{CLASS_NAME}}'] = $className;
                $replacements['{{NAMESPACE}}'] = $namespace;

                $content = str_replace(array_keys($replacements), array_values($replacements), $stubContent);

                $targetPath = "{$targetBasePath}/{$targetFileName}";
                File::ensureDirectoryExists(dirname($targetPath));
                File::put($targetPath, $content);
                $this->info("Created: {$targetPath}");
            }
        }

        $this->info("Module {$module} skeleton created successfully in {$context} context!");
    }
}
