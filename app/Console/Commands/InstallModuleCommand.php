<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Process;

class InstallModuleCommand extends Command
{
    protected $signature = 'module:install {name}';
    protected $description = 'Install a module and its dependencies';

    public function handle(): int
    {
        $name = $this->argument('name');

        $modulePath = $this->findModulePath($name);

        if (!$modulePath) {
            $this->error("Module {$name} not found at {$modulePath}. Make sure it exists in the modules directory.");
            return self::FAILURE;
        }

        $this->info("Installing module: $name");

        $this->mergeComposerDependencies($modulePath);
        $this->mergeNodeDependencies($modulePath);

        $this->runComposer();
        $this->runNpm();

        $this->enableModule($modulePath);

        $this->runModuleMigrations($modulePath);

        $this->call('module:cache');

        $this->info("Module [$name] installed successfully.");

        return self::SUCCESS;
    }

    protected function findModulePath(string $name): ?string
    {
        $paths = [
            base_path("modules/Core/$name"),
            base_path("modules/Extra/$name"),
        ];

        foreach ($paths as $path) {
            if (is_dir($path)) {
                return $path;
            }
        }

        return null;
    }

    protected function mergeComposerDependencies(string $modulePath): void
    {
        $moduleComposer = $modulePath . '/composer.json';

        if (!file_exists($moduleComposer)) {
            $this->info("No composer.json found for module at {$moduleComposer}, skipping composer dependency merge.");
            return;
        }

        $rootComposerPath = base_path('composer.json');

        $root = json_decode(file_get_contents($rootComposerPath), true);
        $module = json_decode(file_get_contents($moduleComposer), true);

        $root['require'] = array_merge(
            $root['require'] ?? [],
            $module['require'] ?? []
        );

        file_put_contents(
            $rootComposerPath,
            json_encode($root, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );

        $this->info("Merge composer dependencies from module's composer.json into root composer.json Completed.");
    }

    protected function mergeNodeDependencies(string $modulePath): void
    {
        $modulePackage = $modulePath . '/package.json';

        if (!file_exists($modulePackage)) {
            $this->info("No package.json found for module at {$modulePackage}, skipping npm dependency merge.");
            return;
        }

        $rootPackagePath = base_path('package.json');

        $root = json_decode(file_get_contents($rootPackagePath), true);
        $module = json_decode(file_get_contents($modulePackage), true);

        $root['dependencies'] = array_merge(
            $root['dependencies'] ?? [],
            $module['dependencies'] ?? []
        );

        file_put_contents(
            $rootPackagePath,
            json_encode($root, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );

        $this->info("Merge npm dependencies from module's package.json into root package.json Completed.");
    }

    protected function runComposer(): void
    {
        $this->info("Running composer update...");

        $process = Process::fromShellCommandline('composer update');
        $process->setTimeout(null);
        $process->run();

        if (!$process->isSuccessful()) {
            $this->error("Composer update failed: " . $process->getErrorOutput());
        }

        $this->info("Composer update completed.");
    }

    protected function runNpm(): void
    {
        $this->info("Running npm install...");

        $process = Process::fromShellCommandline('npm install');
        $process->setTimeout(null);
        $process->run();

        if (!$process->isSuccessful()) {
            $this->error("NPM install failed: " . $process->getErrorOutput());
        }

        $this->info("NPM install completed.");
    }

    protected function enableModule(string $modulePath): void
    {
        $moduleJson = $modulePath . '/module.json';

        $config = json_decode(file_get_contents($moduleJson), true);
        $config['enabled'] = true;

        file_put_contents(
            $moduleJson,
            json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );

        $this->info("Module enabled in module.json.");
    }

    protected function runModuleMigrations(string $modulePath): void
    {
        $migrationPath = $modulePath . '/Database/Migrations';

        if (!is_dir($migrationPath)) {
            return;
        }

        $this->info("Running module migrations...");

        $this->call('migrate', [
            '--path' => str_replace(base_path() . '/', '', $migrationPath),
            '--force' => true,
        ]);
    }
}
