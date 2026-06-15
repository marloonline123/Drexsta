<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;

class MakeModuleFile extends Command
{
    protected $signature = 'module:make
                            {module : The module name (e.g., Company)}
                            {name : The class or file name (e.g., CompanyResource)}
                            {--context=Core : The module context folder}
                            {--class}
                            {--command}
                            {--component}
                            {--controller}
                            {--enum}
                            {--event}
                            {--exception}
                            {--interface}
                            {--job}
                            {--job-middleware}
                            {--listener}
                            {--mail}
                            {--middleware}
                            {--migration}
                            {--model}
                            {--notification}
                            {--observer}
                            {--policy}
                            {--provider}
                            {--request}
                            {--resource}
                            {--rule}
                            {--scope}
                            {--seeder}
                            {--trait}
                            {--view}
                            {--inertia}';

    protected $description = 'Create a file inside a module using the module architecture structure';

    public function handle(): void
    {
        $module  = ucfirst($this->argument('module'));
        $name    = ucfirst($this->argument('name'));
        $context = ucfirst($this->option('context'));
        $type    = $this->resolveType();

        $opts      = $this->typeOptions($type);
        $namespace = $this->buildNamespace($context, $module, $opts['folder']);
        $content   = $this->buildContent($type, $name, $module, $namespace, $opts);
        $fileName  = $this->buildFileName($type, $name);

        $targetPath = base_path("modules/{$context}/{$module}/{$opts['folder']}/{$fileName}");

        File::ensureDirectoryExists(dirname($targetPath));

        if (File::exists($targetPath) && $type !== 'migration') {
            $this->error("File already exists: {$targetPath}");
            return;
        }

        File::put($targetPath, $content);
        $this->info(ucfirst($type) . ' created successfully at: ' . $targetPath);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private function resolveType(): string
    {
        $types = [
            'command', 'component', 'controller', 'enum', 'event', 'exception',
            'interface', 'job', 'job-middleware', 'listener', 'mail', 'middleware',
            'migration', 'model', 'notification', 'observer', 'policy', 'provider',
            'request', 'resource', 'rule', 'scope', 'seeder', 'trait', 'view',
            'inertia', 'class',
        ];

        foreach ($types as $t) {
            if ($this->option($t)) {
                return $t;
            }
        }

        return 'class';
    }

    private function buildNamespace(string $context, string $module, string $folder): string
    {
        $folderNamespace = str_replace('/', '\\', $folder);
        return rtrim("Modules\\{$context}\\{$module}\\{$folderNamespace}", '\\');
    }

    private function buildFileName(string $type, string $name): string
    {
        return match ($type) {
            'view'      => Str::kebab($name) . '.blade.php',
            'inertia'   => $name . '.jsx',
            'migration' => date('Y_m_d_His') . '_create_' . Str::snake(Str::plural($name)) . '_table.php',
            default     => $name . '.php',
        };
    }

    private function typeOptions(string $type): array
    {
        return match ($type) {
            'command'       => ['folder' => 'Ui/Console/Commands',                'extends' => 'Illuminate\Console\Command'],
            'component'     => ['folder' => 'Ui/Resources/Views/Components',      'extends' => 'Illuminate\View\Component'],
            'controller'    => ['folder' => 'Ui/Http/Controllers',                'extends' => 'App\Http\Controllers\Controller'],
            'enum'          => ['folder' => 'Domain/Enums',                       'is_enum'       => true],
            'event'         => ['folder' => 'Domain/Events',                      'extends' => null],
            'exception'     => ['folder' => 'Domain/Exceptions',                  'extends' => 'Exception'],
            'interface'     => ['folder' => 'Domain/Contracts',                   'is_interface'  => true],
            'job'           => ['folder' => 'Application/Jobs',                   'implements'    => 'Illuminate\Contracts\Queue\ShouldQueue'],
            'job-middleware'=> ['folder' => 'Application/Jobs/Middleware',         'extends' => null],
            'listener'      => ['folder' => 'Application/Listeners',              'extends' => null],
            'mail'          => ['folder' => 'Application/Mail',                   'extends' => 'Illuminate\Mail\Mailable'],
            'middleware'    => ['folder' => 'Ui/Http/Middleware',                 'extends' => null],
            'migration'     => ['folder' => 'Database/Migrations',                'is_migration'  => true],
            'model'         => ['folder' => 'Infrastructure/Models',              'extends' => 'Illuminate\Database\Eloquent\Model'],
            'notification'  => ['folder' => 'Application/Notifications',          'extends' => 'Illuminate\Notifications\Notification'],
            'observer'      => ['folder' => 'Infrastructure/Observers',           'extends' => null],
            'policy'        => ['folder' => 'Application/Policies',               'extends' => null],
            'provider'      => ['folder' => 'Providers',                          'extends' => 'Illuminate\Support\ServiceProvider'],
            'request'       => ['folder' => 'Ui/Http/Requests',                  'extends' => 'Illuminate\Foundation\Http\FormRequest'],
            'resource'      => ['folder' => 'Ui/Http/Resources',                 'extends' => 'Illuminate\Http\Resources\Json\JsonResource'],
            'rule'          => ['folder' => 'Domain/Rules',                       'implements'    => 'Illuminate\Contracts\Validation\ValidationRule'],
            'scope'         => ['folder' => 'Infrastructure/Models/Scopes',       'implements'    => 'Illuminate\Database\Eloquent\Scope'],
            'seeder'        => ['folder' => 'Database/Seeders',                   'extends' => 'Illuminate\Database\Seeder'],
            'trait'         => ['folder' => 'Domain/Traits',                      'is_trait'      => true],
            'view'          => ['folder' => 'Ui/Resources/Blade/Views',           'is_view'       => true],
            'inertia'       => ['folder' => 'Ui/Resources/Inertia/Pages',         'is_inertia'    => true],
            default         => ['folder' => 'Domain/Classes',                     'extends' => null],
        };
    }

    private function buildContent(string $type, string $name, string $module, string $namespace, array $opts): string
    {
        // 1. Use a custom stub if available
        $stubPath = base_path("stubs/module/{$type}.stub");
        if (File::exists($stubPath)) {
            return str_replace(
                ['{{MODULE}}', '{{CLASS_NAME}}', '{{NAMESPACE}}'],
                [$module, $name, $namespace],
                File::get($stubPath)
            );
        }

        // 2. On-the-fly generation —————————————————————————————

        if ($type === 'migration') {
            $table = Str::snake(Str::plural($name));
            return <<<PHP
            <?php

            use Illuminate\Database\Migrations\Migration;
            use Illuminate\Database\Schema\Blueprint;
            use Illuminate\Support\Facades\Schema;

            return new class extends Migration
            {
                public function up(): void
                {
                    Schema::create('{$table}', function (Blueprint \$table) {
                        \$table->id();
                        \$table->timestamps();
                    });
                }

                public function down(): void
                {
                    Schema::dropIfExists('{$table}');
                }
            };
            PHP;
        }

        if (isset($opts['is_view'])) {
            return "@extends('layouts.app')\n\n@section('content')\n    <div>\n        <!-- {$name} -->\n    </div>\n@endsection\n";
        }

        if (isset($opts['is_inertia'])) {
            return "import React from 'react';\n\nexport default function {$name}() {\n    return (\n        <div>\n            <h1>{$name}</h1>\n        </div>\n    );\n}\n";
        }

        // PHP class / interface / trait / enum
        $declaration = 'class';
        if (isset($opts['is_interface'])) $declaration = 'interface';
        elseif (isset($opts['is_trait']))  $declaration = 'trait';
        elseif (isset($opts['is_enum']))   $declaration = 'enum';

        $uses = [];

        $extends = '';
        if (!empty($opts['extends'])) {
            $uses[]  = "use {$opts['extends']};";
            $extends = ' extends ' . class_basename($opts['extends']);
        }

        $implements = '';
        if (!empty($opts['implements'])) {
            $uses[]     = "use {$opts['implements']};";
            $implements = ' implements ' . class_basename($opts['implements']);
        }

        $usesBlock = empty($uses) ? '' : implode("\n", $uses) . "\n\n";

        $body = $this->buildMethodBody($type, $name, $module);

        return "<?php\n\nnamespace {$namespace};\n\n{$usesBlock}{$declaration} {$name}{$extends}{$implements}\n{\n{$body}}\n";
    }

    private function buildMethodBody(string $type, string $name, string $module): string
    {
        return match ($type) {
            'command' => implode("\n", [
                "    protected \$signature = '" . strtolower($module) . ':' . Str::kebab(str_replace('Command', '', $name)) . "';",
                "    protected \$description = 'Command description';",
                '',
                '    public function handle(): void',
                '    {',
                '        //',
                '    }',
                '',
            ]),
            'request' => implode("\n", [
                '    public function authorize(): bool',
                '    {',
                '        return true;',
                '    }',
                '',
                '    public function rules(): array',
                '    {',
                '        return [',
                '            //',
                '        ];',
                '    }',
                '',
            ]),
            'resource' => implode("\n", [
                '    public function toArray($request): array',
                '    {',
                '        return parent::toArray($request);',
                '    }',
                '',
            ]),
            'seeder' => implode("\n", [
                '    public function run(): void',
                '    {',
                '        //',
                '    }',
                '',
            ]),
            'middleware' => implode("\n", [
                '    public function handle($request, \Closure $next)',
                '    {',
                '        return $next($request);',
                '    }',
                '',
            ]),
            'job' => implode("\n", [
                '    use \Illuminate\Bus\Queueable;',
                '    use \Illuminate\Queue\InteractsWithQueue;',
                '    use \Illuminate\Queue\SerializesModels;',
                '    use \Illuminate\Foundation\Bus\Dispatchable;',
                '',
                '    public function handle(): void',
                '    {',
                '        //',
                '    }',
                '',
            ]),
            'provider' => implode("\n", [
                '    public function register(): void',
                '    {',
                '        //',
                '    }',
                '',
                '    public function boot(): void',
                '    {',
                '        //',
                '    }',
                '',
            ]),
            'policy' => implode("\n", [
                '    public function viewAny($user): bool { return false; }',
                '    public function view($user, $model): bool { return false; }',
                '    public function create($user): bool { return false; }',
                '    public function update($user, $model): bool { return false; }',
                '    public function delete($user, $model): bool { return false; }',
                '',
            ]),
            'rule' => implode("\n", [
                '    public function passes($attribute, $value): bool',
                '    {',
                '        return true;',
                '    }',
                '',
                '    public function message(): string',
                '    {',
                "        return 'Validation failed.';",
                '    }',
                '',
            ]),
            'observer' => implode("\n", [
                '    public function created($model): void { }',
                '    public function updated($model): void { }',
                '    public function deleted($model): void { }',
                '',
            ]),
            default => "    //\n",
        };
    }
}
