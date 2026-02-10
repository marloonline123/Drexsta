<?php

namespace App\Traits\Tenancy;

use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Facades\Auth;
use Spatie\Permission\Traits\HasRoles as SpatieHasRoles;

trait HasRoles
{
    use SpatieHasRoles;

    /**
     * A model may have multiple roles.
     */
    public function roles(): MorphToMany
    {
        $relation = $this->morphToMany(
            config('permission.models.role'),
            'model',
            config('permission.table_names.model_has_roles'),
            config('permission.column_names.model_morph_key'),
            'role_id'
        );

        if (!Auth::check()) {
            return $relation;
        }

        return $relation->where(config('permission.table_names.roles') . '.company_id', '=', Auth::user()->active_company_id);
    }
}

/**
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 */

use Illuminate\Cache\CacheManager;
use Illuminate\Contracts\Auth\Access\Authorizable;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Cache\Store;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\Contracts\Permission;
use Spatie\Permission\Contracts\PermissionsTeamResolver;
use Spatie\Permission\Contracts\Role;

class PermissionRegistrar
{
    protected Repository $cache;

    protected CacheManager $cacheManager;

    protected string $permissionClass;

    protected string $roleClass;

    /** @var Collection|array|null */
    protected $permissions;

    public string $pivotRole;

    public string $pivotPermission;

    /** @var \DateInterval|int */
    public $cacheExpirationTime;

    public bool $teams;

    protected PermissionsTeamResolver $teamResolver;

    public string $teamsKey;

    public string $cacheKey;

    private array $cachedRoles = [];

    private array $alias = [];

    private array $except = [];

    private array $wildcardPermissionsIndex = [];

    /**
     * PermissionRegistrar constructor.
     */
    public function __construct(CacheManager $cacheManager)
    {
        $this->permissionClass = config('permission.models.permission');
        $this->roleClass = config('permission.models.role');
        $this->teamResolver = new (config('permission.team_resolver', DefaultTeamResolver::class));

        $this->cacheManager = $cacheManager;
        $this->initializeCache();
    }

    public function initializeCache(): void
    {
        $this->cacheExpirationTime = config('permission.cache.expiration_time') ?: \DateInterval::createFromDateString('24 hours');

        $this->teams = config('permission.teams', false);
        $this->teamsKey = config('permission.column_names.team_foreign_key', 'team_id');

        $this->cacheKey = config('permission.cache.key');

        $this->pivotRole = config('permission.column_names.role_pivot_key') ?: 'role_id';
        $this->pivotPermission = config('permission.column_names.permission_pivot_key') ?: 'permission_id';

        $this->cache = $this->getCacheStoreFromConfig();
    }

    protected function getCacheStoreFromConfig(): Repository
    {
        // the 'default' fallback here is from the permission.php config file,
        // where 'default' means to use config(cache.default)
        $cacheDriver = config('permission.cache.store', 'default');

        // when 'default' is specified, no action is required since we already have the default instance
        if ($cacheDriver === 'default') {
            return $this->cacheManager->store();
        }

        // if an undefined cache store is specified, fallback to 'array' which is Laravel's closest equiv to 'none'
        if (! \array_key_exists($cacheDriver, config('cache.stores'))) {
            $cacheDriver = 'array';
        }

        return $this->cacheManager->store($cacheDriver);
    }

    /**
     * Set the team id for teams/groups support, this id is used when querying permissions/roles
     *
     * @param  int|string|\Illuminate\Database\Eloquent\Model|null  $id
     */
    public function setPermissionsTeamId($id): void
    {
        $this->teamResolver->setPermissionsTeamId($id);
    }

    /**
     * @return int|string|null
     */
    public function getPermissionsTeamId()
    {
        return $this->teamResolver->getPermissionsTeamId();
    }

    /**
     * Register the permission check method on the gate.
     * We resolve the Gate fresh here, for benefit of long-running instances.
     */
    public function registerPermissions(Gate $gate): bool
    {
        $gate->before(function (Authorizable $user, string $ability, array &$args = []) {
            if (is_string($args[0] ?? null) && ! class_exists($args[0])) {
                $guard = array_shift($args);
            }
            if (method_exists($user, 'checkPermissionTo')) {
                return $user->checkPermissionTo($ability, $guard ?? null) ?: null;
            }
        });

        return true;
    }

    /**
     * Flush the cache.
     */
    public function forgetCachedPermissions()
    {
        $this->permissions = null;
        $this->forgetWildcardPermissionIndex();

        return $this->cache->forget($this->cacheKey);
    }

    public function forgetWildcardPermissionIndex(?Model $record = null): void
    {
        if ($record) {
            unset($this->wildcardPermissionsIndex[get_class($record)][$record->getKey()]);

            return;
        }

        $this->wildcardPermissionsIndex = [];
    }

    public function getWildcardPermissionIndex(Model $record): array
    {
        if (isset($this->wildcardPermissionsIndex[get_class($record)][$record->getKey()])) {
            return $this->wildcardPermissionsIndex[get_class($record)][$record->getKey()];
        }

        return $this->wildcardPermissionsIndex[get_class($record)][$record->getKey()] = app($record->getWildcardClass(), ['record' => $record])->getIndex();
    }

    /**
     * Clear already-loaded permissions collection.
     * This is only intended to be called by the PermissionServiceProvider on boot,
     * so that long-running instances like Octane or Swoole don't keep old data in memory.
     */
    public function clearPermissionsCollection(): void
    {
        $this->permissions = null;
        $this->wildcardPermissionsIndex = [];
    }

    /**
     * @deprecated
     *
     * @alias of clearPermissionsCollection()
     */
    public function clearClassPermissions()
    {
        $this->clearPermissionsCollection();
    }

    /**
     * Load permissions from cache
     * And turns permissions array into a \Illuminate\Database\Eloquent\Collection
     */
    private function loadPermissions(): void
    {
        if ($this->permissions) {
            return;
        }

        $this->permissions = $this->cache->remember(
            $this->cacheKey,
            $this->cacheExpirationTime,
            fn() => $this->getSerializedPermissionsForCache()
        );

        $this->alias = $this->permissions['alias'];

        $this->hydrateRolesCache();

        $this->permissions = $this->getHydratedPermissionCollection();

        $this->cachedRoles = $this->alias = $this->except = [];
    }

    /**
     * Get the permissions based on the passed params.
     */
    public function getPermissions(array $params = [], bool $onlyOne = false): Collection
    {
        $this->loadPermissions();

        $method = $onlyOne ? 'first' : 'filter';

        $permissions = $this->permissions->$method(static function ($permission) use ($params) {
            foreach ($params as $attr => $value) {
                if ($permission->getAttribute($attr) != $value) {
                    return false;
                }
            }

            return true;
        });

        if ($onlyOne) {
            $permissions = new Collection($permissions ? [$permissions] : []);
        }

        return $permissions;
    }

    public function getPermissionClass(): string
    {
        return $this->permissionClass;
    }

    public function setPermissionClass($permissionClass)
    {
        $this->permissionClass = $permissionClass;
        config()->set('permission.models.permission', $permissionClass);
        app()->bind(Permission::class, $permissionClass);

        return $this;
    }

    public function getRoleClass(): string
    {
        return $this->roleClass;
    }

    public function setRoleClass($roleClass)
    {
        $this->roleClass = $roleClass;
        config()->set('permission.models.role', $roleClass);
        app()->bind(Role::class, $roleClass);

        return $this;
    }

    public function getCacheRepository(): Repository
    {
        return $this->cache;
    }

    public function getCacheStore(): Store
    {
        return $this->cache->getStore();
    }

    protected function getPermissionsWithRoles(): Collection
    {
        return $this->permissionClass::select()->with('roles')->get();
    }

    /**
     * Changes array keys with alias
     */
    private function aliasedArray($model): array
    {
        return collect(is_array($model) ? $model : $model->getAttributes())->except($this->except)
            ->keyBy(fn($value, $key) => $this->alias[$key] ?? $key)
            ->all();
    }

    /**
     * Array for cache alias
     */
    private function aliasModelFields($newKeys = []): void
    {
        $i = 0;
        $alphas = ! count($this->alias) ? range('a', 'h') : range('j', 'p');

        foreach (array_keys($newKeys->getAttributes()) as $value) {
            if (! isset($this->alias[$value])) {
                $this->alias[$value] = $alphas[$i++] ?? $value;
            }
        }

        $this->alias = array_diff_key($this->alias, array_flip($this->except));
    }

    /*
     * Make the cache smaller using an array with only required fields
     */
    private function getSerializedPermissionsForCache(): array
    {
        $this->except = config('permission.cache.column_names_except', ['created_at', 'updated_at', 'deleted_at']);

        $permissions = $this->getPermissionsWithRoles()
            ->map(function ($permission) {
                if (! $this->alias) {
                    $this->aliasModelFields($permission);
                }

                return $this->aliasedArray($permission) + $this->getSerializedRoleRelation($permission);
            })->all();
        $roles = array_values($this->cachedRoles);
        $this->cachedRoles = [];

        return ['alias' => array_flip($this->alias)] + compact('permissions', 'roles');
    }

    private function getSerializedRoleRelation($permission): array
    {
        if (! $permission->roles->count()) {
            return [];
        }

        if (! isset($this->alias['roles'])) {
            $this->alias['roles'] = 'r';
            $this->aliasModelFields($permission->roles[0]);
        }

        return [
            'r' => $permission->roles->map(function ($role) {
                if (! isset($this->cachedRoles[$role->getKey()])) {
                    $this->cachedRoles[$role->getKey()] = $this->aliasedArray($role);
                }

                return $role->getKey();
            })->all(),
        ];
    }

    private function getHydratedPermissionCollection(): Collection
    {
        $permissionInstance = (new ($this->getPermissionClass())())->newInstance([], true);

        return Collection::make(array_map(
            fn($item) => (clone $permissionInstance)
                ->setRawAttributes($this->aliasedArray(array_diff_key($item, ['r' => 0])), true)
                ->setRelation('roles', $this->getHydratedRoleCollection($item['r'] ?? [])),
            $this->permissions['permissions']
        ));
    }

    private function getHydratedRoleCollection(array $roles): Collection
    {
        return Collection::make(array_values(
            array_intersect_key($this->cachedRoles, array_flip($roles))
        ));
    }

    private function hydrateRolesCache(): void
    {
        $roleInstance = (new ($this->getRoleClass())())->newInstance([], true);

        array_map(function ($item) use ($roleInstance) {
            $role = (clone $roleInstance)
                ->setRawAttributes($this->aliasedArray($item), true);
            $this->cachedRoles[$role->getKey()] = $role;
        }, $this->permissions['roles']);

        $this->permissions['roles'] = [];
    }

    public static function isUid($value): bool
    {
        if (! is_string($value) || empty(trim($value))) {
            return false;
        }

        // check if is UUID/GUID
        $uid = preg_match('/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/iD', $value) > 0;
        if ($uid) {
            return true;
        }

        // check if is ULID
        $ulid = strlen($value) == 26 && strspn($value, '0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyz') == 26 && $value[0] <= '7';
        if ($ulid) {
            return true;
        }

        return false;
    }
}


/**
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 */


use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Spatie\Permission\Contracts\Permission;
use Spatie\Permission\Contracts\Role;
use Spatie\Permission\Events\RoleAttached;
use Spatie\Permission\Events\RoleDetached;
use Spatie\Permission\PermissionRegistrar;

trait HasRoles
{
    use HasPermissions;

    private ?string $roleClass = null;

    public static function bootHasRoles()
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            $teams = app(PermissionRegistrar::class)->teams;
            app(PermissionRegistrar::class)->teams = false;
            $model->roles()->detach();
            if (is_a($model, Permission::class)) {
                $model->users()->detach();
            }
            app(PermissionRegistrar::class)->teams = $teams;
        });
    }

    public function getRoleClass(): string
    {
        if (! $this->roleClass) {
            $this->roleClass = app(PermissionRegistrar::class)->getRoleClass();
        }

        return $this->roleClass;
    }

    /**
     * A model may have multiple roles.
     */
    public function roles(): BelongsToMany
    {
        $relation = $this->morphToMany(
            config('permission.models.role'),
            'model',
            config('permission.table_names.model_has_roles'),
            config('permission.column_names.model_morph_key'),
            app(PermissionRegistrar::class)->pivotRole
        );

        if (! app(PermissionRegistrar::class)->teams) {
            return $relation;
        }

        $teamsKey = app(PermissionRegistrar::class)->teamsKey;
        $relation->withPivot($teamsKey);
        $teamField = config('permission.table_names.roles') . '.' . $teamsKey;

        return $relation->wherePivot($teamsKey, getPermissionsTeamId())
            ->where(fn($q) => $q->whereNull($teamField)->orWhere($teamField, getPermissionsTeamId()));
    }

    /**
     * Scope the model query to certain roles only.
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  $roles
     * @param  string  $guard
     * @param  bool  $without
     */
    public function scopeRole(Builder $query, $roles, $guard = null, $without = false): Builder
    {
        if ($roles instanceof Collection) {
            $roles = $roles->all();
        }

        $roles = array_map(function ($role) use ($guard) {
            if ($role instanceof Role) {
                return $role;
            }

            if ($role instanceof \BackedEnum) {
                $role = $role->value;
            }

            $method = is_int($role) || PermissionRegistrar::isUid($role) ? 'findById' : 'findByName';

            return $this->getRoleClass()::{$method}($role, $guard ?: $this->getDefaultGuardName());
        }, Arr::wrap($roles));

        $key = (new ($this->getRoleClass())())->getKeyName();

        return $query->{! $without ? 'whereHas' : 'whereDoesntHave'}(
            'roles',
            fn(Builder $subQuery) => $subQuery
                ->whereIn(config('permission.table_names.roles') . ".$key", \array_column($roles, $key))
        );
    }

    /**
     * Scope the model query to only those without certain roles.
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  $roles
     * @param  string  $guard
     */
    public function scopeWithoutRole(Builder $query, $roles, $guard = null): Builder
    {
        return $this->scopeRole($query, $roles, $guard, true);
    }

    /**
     * Returns array of role ids
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  $roles
     */
    private function collectRoles(...$roles): array
    {
        return collect($roles)
            ->flatten()
            ->reduce(function ($array, $role) {
                if (empty($role)) {
                    return $array;
                }

                $role = $this->getStoredRole($role);

                if (! in_array($role->getKey(), $array)) {
                    $this->ensureModelSharesGuard($role);
                    $array[] = $role->getKey();
                }

                return $array;
            }, []);
    }

    /**
     * Assign the given role to the model.
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  ...$roles
     * @return $this
     */
    public function assignRole(...$roles)
    {
        $roles = $this->collectRoles($roles);

        $model = $this->getModel();
        $teamPivot = app(PermissionRegistrar::class)->teams && ! is_a($this, Permission::class) ?
            [app(PermissionRegistrar::class)->teamsKey => getPermissionsTeamId()] : [];

        if ($model->exists) {
            if (app(PermissionRegistrar::class)->teams) {
                // explicit reload in case team has been changed since last load
                $this->load('roles');
            }

            $currentRoles = $this->roles->map(fn($role) => $role->getKey())->toArray();

            $this->roles()->attach(array_diff($roles, $currentRoles), $teamPivot);
            $model->unsetRelation('roles');
        } else {
            $class = \get_class($model);
            $saved = false;

            $class::saved(
                function ($object) use ($roles, $model, $teamPivot, &$saved) {
                    if ($saved || $model->getKey() != $object->getKey()) {
                        return;
                    }
                    $model->roles()->attach($roles, $teamPivot);
                    $model->unsetRelation('roles');
                    $saved = true;
                }
            );
        }

        if (is_a($this, Permission::class)) {
            $this->forgetCachedPermissions();
        }

        if (config('permission.events_enabled')) {
            event(new RoleAttached($this->getModel(), $roles));
        }

        return $this;
    }

    /**
     * Revoke the given role from the model.
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  ...$role
     * @return $this
     */
    public function removeRole(...$role)
    {
        $roles = $this->collectRoles($role);

        $this->roles()->detach($roles);

        $this->unsetRelation('roles');

        if (is_a($this, Permission::class)) {
            $this->forgetCachedPermissions();
        }

        if (config('permission.events_enabled')) {
            event(new RoleDetached($this->getModel(), $roles));
        }

        return $this;
    }

    /**
     * Remove all current roles and set the given ones.
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  ...$roles
     * @return $this
     */
    public function syncRoles(...$roles)
    {
        if ($this->getModel()->exists) {
            $this->collectRoles($roles);
            $this->roles()->detach();
            $this->setRelation('roles', collect());
        }

        return $this->assignRole($roles);
    }

    /**
     * Determine if the model has (one of) the given role(s).
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  $roles
     */
    public function hasRole($roles, ?string $guard = null): bool
    {
        $this->loadMissing('roles');

        if (is_string($roles) && strpos($roles, '|') !== false) {
            $roles = $this->convertPipeToArray($roles);
        }

        if ($roles instanceof \BackedEnum) {
            $roles = $roles->value;

            return $this->roles
                ->when($guard, fn($q) => $q->where('guard_name', $guard))
                ->pluck('name')
                ->contains(function ($name) use ($roles) {
                    /** @var string|\BackedEnum $name */
                    if ($name instanceof \BackedEnum) {
                        return $name->value == $roles;
                    }

                    return $name == $roles;
                });
        }

        if (is_int($roles) || PermissionRegistrar::isUid($roles)) {
            $key = (new ($this->getRoleClass())())->getKeyName();

            return $guard
                ? $this->roles->where('guard_name', $guard)->contains($key, $roles)
                : $this->roles->contains($key, $roles);
        }

        if (is_string($roles)) {
            return $guard
                ? $this->roles->where('guard_name', $guard)->contains('name', $roles)
                : $this->roles->contains('name', $roles);
        }

        if ($roles instanceof Role) {
            return $this->roles->contains($roles->getKeyName(), $roles->getKey());
        }

        if (is_array($roles)) {
            foreach ($roles as $role) {
                if ($this->hasRole($role, $guard)) {
                    return true;
                }
            }

            return false;
        }

        if ($roles instanceof Collection) {
            return $roles->intersect($guard ? $this->roles->where('guard_name', $guard) : $this->roles)->isNotEmpty();
        }

        throw new \TypeError('Unsupported type for $roles parameter to hasRole().');
    }

    /**
     * Determine if the model has any of the given role(s).
     *
     * Alias to hasRole() but without Guard controls
     *
     * @param  string|int|array|Role|Collection|\BackedEnum  $roles
     */
    public function hasAnyRole(...$roles): bool
    {
        return $this->hasRole($roles);
    }

    /**
     * Determine if the model has all of the given role(s).
     *
     * @param  string|array|Role|Collection|\BackedEnum  $roles
     */
    public function hasAllRoles($roles, ?string $guard = null): bool
    {
        $this->loadMissing('roles');

        if ($roles instanceof \BackedEnum) {
            $roles = $roles->value;
        }

        if (is_string($roles) && strpos($roles, '|') !== false) {
            $roles = $this->convertPipeToArray($roles);
        }

        if (is_string($roles)) {
            return $this->hasRole($roles, $guard);
        }

        if ($roles instanceof Role) {
            return $this->roles->contains($roles->getKeyName(), $roles->getKey());
        }

        $roles = collect()->make($roles)->map(function ($role) {
            if ($role instanceof \BackedEnum) {
                return $role->value;
            }

            return $role instanceof Role ? $role->name : $role;
        });

        $roleNames = $guard
            ? $this->roles->where('guard_name', $guard)->pluck('name')
            : $this->getRoleNames();

        $roleNames = $roleNames->transform(function ($roleName) {
            if ($roleName instanceof \BackedEnum) {
                return $roleName->value;
            }

            return $roleName;
        });

        return $roles->intersect($roleNames) == $roles;
    }

    /**
     * Determine if the model has exactly all of the given role(s).
     *
     * @param  string|array|Role|Collection|\BackedEnum  $roles
     */
    public function hasExactRoles($roles, ?string $guard = null): bool
    {
        $this->loadMissing('roles');

        if (is_string($roles) && strpos($roles, '|') !== false) {
            $roles = $this->convertPipeToArray($roles);
        }

        if (is_string($roles)) {
            $roles = [$roles];
        }

        if ($roles instanceof Role) {
            $roles = [$roles->name];
        }

        $roles = collect()->make($roles)->map(
            fn($role) => $role instanceof Role ? $role->name : $role
        );

        return $this->roles->count() == $roles->count() && $this->hasAllRoles($roles, $guard);
    }

    /**
     * Return all permissions directly coupled to the model.
     */
    public function getDirectPermissions(): Collection
    {
        return $this->permissions;
    }

    public function getRoleNames(): Collection
    {
        $this->loadMissing('roles');

        return $this->roles->pluck('name');
    }

    protected function getStoredRole($role): Role
    {
        if ($role instanceof \BackedEnum) {
            $role = $role->value;
        }

        if (is_int($role) || PermissionRegistrar::isUid($role)) {
            return $this->getRoleClass()::findById($role, $this->getDefaultGuardName());
        }

        if (is_string($role)) {
            return $this->getRoleClass()::findByName($role, $this->getDefaultGuardName());
        }

        return $role;
    }

    protected function convertPipeToArray(string $pipeString)
    {
        $pipeString = trim($pipeString);

        if (strlen($pipeString) <= 2) {
            return [str_replace('|', '', $pipeString)];
        }

        $quoteCharacter = substr($pipeString, 0, 1);
        $endCharacter = substr($quoteCharacter, -1, 1);

        if ($quoteCharacter !== $endCharacter) {
            return explode('|', $pipeString);
        }

        if (! in_array($quoteCharacter, ["'", '"'])) {
            return explode('|', $pipeString);
        }

        return explode('|', trim($pipeString, $quoteCharacter));
    }
}

/**
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 ****************
 */

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Spatie\Permission\Contracts\Permission;
use Spatie\Permission\Contracts\Role;
use Spatie\Permission\Contracts\Wildcard;
use Spatie\Permission\Events\PermissionAttached;
use Spatie\Permission\Events\PermissionDetached;
use Spatie\Permission\Exceptions\GuardDoesNotMatch;
use Spatie\Permission\Exceptions\PermissionDoesNotExist;
use Spatie\Permission\Exceptions\WildcardPermissionInvalidArgument;
use Spatie\Permission\Exceptions\WildcardPermissionNotImplementsContract;
use Spatie\Permission\Guard;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\WildcardPermission;

trait HasPermissions
{
    private ?string $permissionClass = null;

    private ?string $wildcardClass = null;

    private array $wildcardPermissionsIndex;

    public static function bootHasPermissions()
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            $teams = app(PermissionRegistrar::class)->teams;
            app(PermissionRegistrar::class)->teams = false;
            if (! is_a($model, Permission::class)) {
                $model->permissions()->detach();
            }
            if (is_a($model, Role::class)) {
                $model->users()->detach();
            }
            app(PermissionRegistrar::class)->teams = $teams;
        });
    }

    public function getPermissionClass(): string
    {
        if (! $this->permissionClass) {
            $this->permissionClass = app(PermissionRegistrar::class)->getPermissionClass();
        }

        return $this->permissionClass;
    }

    public function getWildcardClass()
    {
        if (! is_null($this->wildcardClass)) {
            return $this->wildcardClass;
        }

        $this->wildcardClass = '';

        if (config('permission.enable_wildcard_permission')) {
            $this->wildcardClass = config('permission.wildcard_permission', WildcardPermission::class);

            if (! is_subclass_of($this->wildcardClass, Wildcard::class)) {
                throw WildcardPermissionNotImplementsContract::create();
            }
        }

        return $this->wildcardClass;
    }

    /**
     * A model may have multiple direct permissions.
     */
    public function permissions(): BelongsToMany
    {
        $relation = $this->morphToMany(
            config('permission.models.permission'),
            'model',
            config('permission.table_names.model_has_permissions'),
            config('permission.column_names.model_morph_key'),
            app(PermissionRegistrar::class)->pivotPermission
        );

        if (! app(PermissionRegistrar::class)->teams) {
            return $relation;
        }

        $teamsKey = app(PermissionRegistrar::class)->teamsKey;
        $relation->withPivot($teamsKey);

        return $relation->wherePivot($teamsKey, getPermissionsTeamId());
    }

    /**
     * Scope the model query to certain permissions only.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     * @param  bool  $without
     */
    public function scopePermission(Builder $query, $permissions, $without = false): Builder
    {
        $permissions = $this->convertToPermissionModels($permissions);

        $permissionKey = (new ($this->getPermissionClass())())->getKeyName();
        $roleKey = (new (is_a($this, Role::class) ? static::class : $this->getRoleClass())())->getKeyName();

        $rolesWithPermissions = is_a($this, Role::class) ? [] : array_unique(
            array_reduce($permissions, fn($result, $permission) => array_merge($result, $permission->roles->all()), [])
        );

        return $query->where(
            fn(Builder $query) => $query
                ->{! $without ? 'whereHas' : 'whereDoesntHave'}(
                    'permissions',
                    fn(Builder $subQuery) => $subQuery
                        ->whereIn(config('permission.table_names.permissions') . ".$permissionKey", \array_column($permissions, $permissionKey))
                )
                ->when(
                    count($rolesWithPermissions),
                    fn($whenQuery) => $whenQuery
                        ->{! $without ? 'orWhereHas' : 'whereDoesntHave'}(
                            'roles',
                            fn(Builder $subQuery) => $subQuery
                                ->whereIn(config('permission.table_names.roles') . ".$roleKey", \array_column($rolesWithPermissions, $roleKey))
                        )
                )
        );
    }

    /**
     * Scope the model query to only those without certain permissions,
     * whether indirectly by role or by direct permission.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     */
    public function scopeWithoutPermission(Builder $query, $permissions): Builder
    {
        return $this->scopePermission($query, $permissions, true);
    }

    /**
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     *
     * @throws PermissionDoesNotExist
     */
    protected function convertToPermissionModels($permissions): array
    {
        if ($permissions instanceof Collection) {
            $permissions = $permissions->all();
        }

        return array_map(function ($permission) {
            if ($permission instanceof Permission) {
                return $permission;
            }

            if ($permission instanceof \BackedEnum) {
                $permission = $permission->value;
            }

            $method = is_int($permission) || PermissionRegistrar::isUid($permission) ? 'findById' : 'findByName';

            return $this->getPermissionClass()::{$method}($permission, $this->getDefaultGuardName());
        }, Arr::wrap($permissions));
    }

    /**
     * Find a permission.
     *
     * @param  string|int|Permission|\BackedEnum  $permission
     * @return Permission
     *
     * @throws PermissionDoesNotExist
     */
    public function filterPermission($permission, $guardName = null)
    {
        if ($permission instanceof \BackedEnum) {
            $permission = $permission->value;
        }

        if (is_int($permission) || PermissionRegistrar::isUid($permission)) {
            $permission = $this->getPermissionClass()::findById(
                $permission,
                $guardName ?? $this->getDefaultGuardName()
            );
        }

        if (is_string($permission)) {
            $permission = $this->getPermissionClass()::findByName(
                $permission,
                $guardName ?? $this->getDefaultGuardName()
            );
        }

        if (! $permission instanceof Permission) {
            throw new PermissionDoesNotExist;
        }

        return $permission;
    }

    /**
     * Determine if the model may perform the given permission.
     *
     * @param  string|int|Permission|\BackedEnum  $permission
     * @param  string|null  $guardName
     *
     * @throws PermissionDoesNotExist
     */
    public function hasPermissionTo($permission, $guardName = null): bool
    {
        if ($this->getWildcardClass()) {
            return $this->hasWildcardPermission($permission, $guardName);
        }

        $permission = $this->filterPermission($permission, $guardName);

        return $this->hasDirectPermission($permission) || $this->hasPermissionViaRole($permission);
    }

    /**
     * Validates a wildcard permission against all permissions of a user.
     *
     * @param  string|int|Permission|\BackedEnum  $permission
     * @param  string|null  $guardName
     */
    protected function hasWildcardPermission($permission, $guardName = null): bool
    {
        $guardName = $guardName ?? $this->getDefaultGuardName();

        if ($permission instanceof \BackedEnum) {
            $permission = $permission->value;
        }

        if (is_int($permission) || PermissionRegistrar::isUid($permission)) {
            $permission = $this->getPermissionClass()::findById($permission, $guardName);
        }

        if ($permission instanceof Permission) {
            $guardName = $permission->guard_name ?? $guardName;
            $permission = $permission->name;
        }

        if (! is_string($permission)) {
            throw WildcardPermissionInvalidArgument::create();
        }

        return app($this->getWildcardClass(), ['record' => $this])->implies(
            $permission,
            $guardName,
            app(PermissionRegistrar::class)->getWildcardPermissionIndex($this),
        );
    }

    /**
     * An alias to hasPermissionTo(), but avoids throwing an exception.
     *
     * @param  string|int|Permission|\BackedEnum  $permission
     * @param  string|null  $guardName
     */
    public function checkPermissionTo($permission, $guardName = null): bool
    {
        try {
            return $this->hasPermissionTo($permission, $guardName);
        } catch (PermissionDoesNotExist $e) {
            return false;
        }
    }

    /**
     * Determine if the model has any of the given permissions.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  ...$permissions
     */
    public function hasAnyPermission(...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if ($this->checkPermissionTo($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the model has all of the given permissions.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  ...$permissions
     */
    public function hasAllPermissions(...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if (! $this->checkPermissionTo($permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine if the model has, via roles, the given permission.
     */
    protected function hasPermissionViaRole(Permission $permission): bool
    {
        if (is_a($this, Role::class)) {
            return false;
        }

        return $this->hasRole($permission->roles);
    }

    /**
     * Determine if the model has the given permission.
     *
     * @param  string|int|Permission|\BackedEnum  $permission
     *
     * @throws PermissionDoesNotExist
     */
    public function hasDirectPermission($permission): bool
    {
        $permission = $this->filterPermission($permission);

        return $this->loadMissing('permissions')->permissions
            ->contains($permission->getKeyName(), $permission->getKey());
    }

    /**
     * Return all the permissions the model has via roles.
     */
    public function getPermissionsViaRoles(): Collection
    {
        if (is_a($this, Role::class) || is_a($this, Permission::class)) {
            return collect();
        }

        return $this->loadMissing('roles', 'roles.permissions')
            ->roles->flatMap(fn($role) => $role->permissions)
            ->sort()->values();
    }

    /**
     * Return all the permissions the model has, both directly and via roles.
     */
    public function getAllPermissions(): Collection
    {
        /** @var Collection $permissions */
        $permissions = $this->permissions;

        if (! is_a($this, Permission::class)) {
            $permissions = $permissions->merge($this->getPermissionsViaRoles());
        }

        return $permissions->sort()->values();
    }

    /**
     * Returns array of permissions ids
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     */
    private function collectPermissions(...$permissions): array
    {
        return collect($permissions)
            ->flatten()
            ->reduce(function ($array, $permission) {
                if (empty($permission)) {
                    return $array;
                }

                $permission = $this->getStoredPermission($permission);
                if (! $permission instanceof Permission) {
                    return $array;
                }

                if (! in_array($permission->getKey(), $array)) {
                    $this->ensureModelSharesGuard($permission);
                    $array[] = $permission->getKey();
                }

                return $array;
            }, []);
    }

    /**
     * Grant the given permission(s) to a role.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     * @return $this
     */
    public function givePermissionTo(...$permissions)
    {
        $permissions = $this->collectPermissions($permissions);

        $model = $this->getModel();
        $teamPivot = app(PermissionRegistrar::class)->teams && ! is_a($this, Role::class) ?
            [app(PermissionRegistrar::class)->teamsKey => getPermissionsTeamId()] : [];

        if ($model->exists) {
            $currentPermissions = $this->permissions->map(fn($permission) => $permission->getKey())->toArray();

            $this->permissions()->attach(array_diff($permissions, $currentPermissions), $teamPivot);
            $model->unsetRelation('permissions');
        } else {
            $class = \get_class($model);
            $saved = false;

            $class::saved(
                function ($object) use ($permissions, $model, $teamPivot, &$saved) {
                    if ($saved || $model->getKey() != $object->getKey()) {
                        return;
                    }
                    $model->permissions()->attach($permissions, $teamPivot);
                    $model->unsetRelation('permissions');
                    $saved = true;
                }
            );
        }

        if (is_a($this, Role::class)) {
            $this->forgetCachedPermissions();
        }

        if (config('permission.events_enabled')) {
            event(new PermissionAttached($this->getModel(), $permissions));
        }

        $this->forgetWildcardPermissionIndex();

        return $this;
    }

    public function forgetWildcardPermissionIndex(): void
    {
        app(PermissionRegistrar::class)->forgetWildcardPermissionIndex(
            is_a($this, Role::class) ? null : $this,
        );
    }

    /**
     * Remove all current permissions and set the given ones.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     * @return $this
     */
    public function syncPermissions(...$permissions)
    {
        if ($this->getModel()->exists) {
            $this->collectPermissions($permissions);
            $this->permissions()->detach();
            $this->setRelation('permissions', collect());
        }

        return $this->givePermissionTo($permissions);
    }

    /**
     * Revoke the given permission(s).
     *
     * @param  Permission|Permission[]|string|string[]|\BackedEnum  $permission
     * @return $this
     */
    public function revokePermissionTo($permission)
    {
        $storedPermission = $this->getStoredPermission($permission);

        $this->permissions()->detach($storedPermission);

        if (is_a($this, Role::class)) {
            $this->forgetCachedPermissions();
        }

        if (config('permission.events_enabled')) {
            event(new PermissionDetached($this->getModel(), $storedPermission));
        }

        $this->forgetWildcardPermissionIndex();

        $this->unsetRelation('permissions');

        return $this;
    }

    public function getPermissionNames(): Collection
    {
        return $this->permissions->pluck('name');
    }

    /**
     * @param  string|int|array|Permission|Collection|\BackedEnum  $permissions
     * @return Permission|Permission[]|Collection
     */
    protected function getStoredPermission($permissions)
    {
        if ($permissions instanceof \BackedEnum) {
            $permissions = $permissions->value;
        }

        if (is_int($permissions) || PermissionRegistrar::isUid($permissions)) {
            return $this->getPermissionClass()::findById($permissions, $this->getDefaultGuardName());
        }

        if (is_string($permissions)) {
            return $this->getPermissionClass()::findByName($permissions, $this->getDefaultGuardName());
        }

        if (is_array($permissions)) {
            $permissions = array_map(function ($permission) {
                if ($permission instanceof \BackedEnum) {
                    return $permission->value;
                }

                return is_a($permission, Permission::class) ? $permission->name : $permission;
            }, $permissions);

            return $this->getPermissionClass()::whereIn('name', $permissions)
                ->whereIn('guard_name', $this->getGuardNames())
                ->get();
        }

        return $permissions;
    }

    /**
     * @param  Permission|Role  $roleOrPermission
     *
     * @throws GuardDoesNotMatch
     */
    protected function ensureModelSharesGuard($roleOrPermission)
    {
        if (! $this->getGuardNames()->contains($roleOrPermission->guard_name)) {
            throw GuardDoesNotMatch::create($roleOrPermission->guard_name, $this->getGuardNames());
        }
    }

    protected function getGuardNames(): Collection
    {
        return Guard::getNames($this);
    }

    protected function getDefaultGuardName(): string
    {
        return Guard::getDefaultName($this);
    }

    /**
     * Forget the cached permissions.
     */
    public function forgetCachedPermissions()
    {
        app(PermissionRegistrar::class)->forgetCachedPermissions();
    }

    /**
     * Check if the model has All of the requested Direct permissions.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  ...$permissions
     */
    public function hasAllDirectPermissions(...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if (! $this->hasDirectPermission($permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if the model has Any of the requested Direct permissions.
     *
     * @param  string|int|array|Permission|Collection|\BackedEnum  ...$permissions
     */
    public function hasAnyDirectPermission(...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if ($this->hasDirectPermission($permission)) {
                return true;
            }
        }

        return false;
    }
}
