<?php
/**
 * sFire Framework (https://sfire.io)
 *
 * @link      https://github.com/sfire-framework/ for the canonical source repository
 * @copyright Copyright (c) 2014-2020 sFire Framework.
 * @license   http://sfire.io/license BSD 3-CLAUSE LICENSE
 */

declare(strict_types=1);

namespace sFire\Permissions;


/**
 * Interface AclInterface
 * @package sFire\Permissions
 */
interface AclInterface {


    /**
     * Returns all the roles as an array
     * @return array
     */
	public function getRoles(): array;


    /**
     * Add a new role with optional settings resources
     * @param string $role The role name
     * @param array $resources All the resources that the role is allowed or denied
     * @param bool $allowed Bool True to allow the role to the given resources, False if role is denied to given resources
     */
	public function addRole(string $role, ?array $resources = null, bool $allowed = true);


    /**
     * Remove a single role with all resources.
     * @param string $role The name of the role
     * @return bool Returns true if successfully removed, false if role could not be found
     */
	public function removeRole(string $role): bool;


    /**
     * Returns if a role is allowed access to the resource
     * @param string $role The role name
     * @param string $resource The name of the resource
     * @return bool True if role is allowed, false if is denied
     */
	public function isAllowed(string $role, string $resource): bool;


    /**
     * Returns if a role is denied access to the resource
     * @param string $role The role name
     * @param string $resource The name of the resource
     * @return bool True if role is denied, false if is allowed
     */
	public function isDenied(string $role, string $resource): bool;


    /**
     * Allow a single or multiple roles by a single or multiple resources
     * @param string|array $roles A single role name or an array with role names
     * @param string|array $resources A single resource or an array with resources
     */
	public function allow($roles, $resources);


    /**
     * Deny a single or multiple roles by a single or multiple resources
     * @param string|array $roles A single role name or an array with role names
     * @param string|array $resources A single resource or an array with resources
     */
	public function deny($roles, $resources);


    /**
     * Let a single or multiple roles inherit the resources of other single or multiple roles
     * @param string|array $roles A single or multiple role name
     * @param string|array $inherits A single or multiple role name
     */
	public function inherit($roles, $inherits);
}