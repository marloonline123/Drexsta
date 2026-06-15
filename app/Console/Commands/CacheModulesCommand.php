<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class CacheModulesCommand extends Command
{
    protected $signature = 'module:cache';
    protected $description = 'Cache enabled modules';

    public function handle(): int
    {
        $modules = [];

        $paths = [
            base_path('modules/Core'),
            base_path('modules/Extra'),
        ];

        foreach ($paths as $path) {
            if (!is_dir($path)) continue;

            foreach (glob($path . '/*', GLOB_ONLYDIR) as $modulePath) {

                $moduleJson = $modulePath . '/module.json';

                if (!file_exists($moduleJson)) continue;

                $config = json_decode(file_get_contents($moduleJson), true);

                if (!($config['enabled'] ?? false)) continue;

                $modules[] = $config['provider'] ?? null;
            }
        }

        $cachePath = base_path('bootstrap/cache/modules.php');

        File::put(
            $cachePath,
            '<?php return ' . var_export($modules, true) . ';'
        );

        $this->info('Modules cached successfully.');

        return self::SUCCESS;
    }
}
