<?php
/**
 * sFire Framework (https://sfire.io)
 *
 * @link      https://github.com/sfire-framework/ for the canonical source repository
 * @copyright Copyright (c) 2014-2020 sFire Framework.
 * @license   http://sfire.io/license BSD 3-CLAUSE LICENSE
 */

declare(strict_types=1);

namespace sFire\Permissions\Acl;

use sFire\Permissions\AclInterface;
use sFire\Permissions\Exception\InvalidArgumentException;


/**
 * Class Acl
 * @package sFire\Permissions
 */
class Acl implements AclInterface {


	/**
	 * Contains all the roles
	 * @var array
	 */
	private array $roles = [];


	/**
	 * Returns all the roles as an array
	 * @return array
	 */
	public function getRoles(): array {
		return $this -> roles;
	}


    /**
     * Returns a single role if found
     * @param string $role The role to be returned
     * @return null|Role NULL if role could not be found, a Role otherwise
     */
	public function getRole(string $role): ?Role {
        return $this -> roles[$role] ?? null;
	}


    /**
     * Add a new role with optional settings resources
     * @param string $role The role name
     * @param array $resources All the resources that the role is allowed or denied
     * @param bool $allowed Bool True to allow the role to the given resources, False if role is denied to given resources
     * @return Role
     */
	public function addRole(string $role, ?array $resources = null, bool $allowed = true): Role {
		
		$this -> roles[$role] = new Role($role);
		$role = $this -> roles[$role];

		if(null !== $resources) {

			if(true === $allowed) {
				$this -> allow($role -> getRole(), $resources);
			}
			else {
				$this -> deny($role -> getRole(), $resources);
			}
		}

		return $role;
	}


    /**
     * Add new roles as array with optional settings resources
     * @param array $roles An array with role names
     * @param array $resources All the resources that the roles are allowed or denied
     * @param bool $allowed Bool True to allow the roles to the given resources, False if roles are denied to given resources
     * @return array Contains all the added roles
     */
	public function addRoles(array $roles, array $resources = null, bool $allowed = true): array {
		
		$output = [];

		foreach($roles as $role) {
			$output[] = $this -> addRole($role, $resources, $allowed);
		}

		return $output;
	}


	/**
	 * Remove a single role with all resources.
	 * @param string $role The name of the role
	 * @return bool Returns true if successfully removed, false if role could not be found
	 */
	public function removeRole(string $role): bool {
		
		//Check if role exists
		if(true === isset($this -> roles[$role])) {
			
			unset($this -> roles[$role]);
			return true;
		}

		return false;
	}


	/**
	 * Returns all the resources as an array
	 * @param string|null $match [optional] When given, only the resources which match the $match will be returned
	 * @return array
	 */
	public function getResources(string $match = null): array {

		$resources = [];

		foreach($this -> roles as $role) {
			$resources = array_merge($role -> getResources($match), $resources);
		}

		return array_keys($resources);
	}


	/**
	 * Returns all the resources with corresponding roles as an array
	 * @return array
	 */
	public function getResourcesWithRoles(): array {

		$resources = [];

		foreach($this -> getResources() as $resource) {

			$resources[$resource] ??= ['allowed' => [], 'denied'  => []];

			foreach($this -> roles as $role) {

				if(true === $role -> isAllowed($resource)) {
					$resources[$resource]['allowed'][] = $role;
				}
				else {
					$resources[$resource]['denied'][] = $role;
				}
			}
		}

		return $resources;
	}


	/**
	 * Returns if a role is allowed access to the resource
	 * @param string $role The role name
	 * @param string $resource The name of the resource
	 * @return bool True if role is allowed, false if is denied
	 */
	public function isAllowed(string $role, string $resource): bool {

		if(true === isset($this -> roles[$role])) {
			return $this -> roles[$role] -> isAllowed($resource);
		}

		return false;
	}


	/**
	 * Returns if a role is denied access to the resource
	 * @param string $role The role name
	 * @param string $resource The name of the resource
	 * @return bool True if role is denied, false if is allowed
	 */
	public function isDenied(string $role, string $resource): bool {
		return false === $this -> isAllowed($role, $resource);
	}


    /**
     * Allow a single or multiple roles by a single or multiple resources
     * @param string|array $roles A single role name or an array with role names
     * @param string|array $resources A single resource or an array with resources
     * @return self
     */
	public function allow($roles, $resources): self {
		return $this -> fill($roles, $resources, true);
	}


    /**
     * Deny a single or multiple roles by a single or multiple resources
     * @param string|array $roles A single role name or an array with role names
     * @param string|array $resources A single resource or an array with resources
     * @return self
     */
	public function deny($roles, $resources): self {
		return $this -> fill($roles, $resources, false);
	}


    /**
     * Let a single or multiple roles inherit the resources of other single or multiple roles
     * @param string|array $roles A single or multiple role name
     * @param string|array $inherits A single or multiple role name
     * @return self
     */
	public function inherit($roles, $inherits): self {

        $roles    = $this -> convertResource($roles);
        $inherits = $this -> convertResource($inherits);

		foreach($inherits as $inherit) {

			if(true === isset($this -> roles[$inherit])) {

				//Gather the resources from the role that needs to be inherit
				$resources = $this -> roles[$inherit] -> getResources();

				foreach($resources as $resource => $allowed) {

					foreach($roles as $role) {

						//Check inherit is allowed and give the rule the same rights
						if(true === $allowed) {
							$this -> allow($role, $resource);
						}
						else {
							$this -> deny($role, $resource);	
						}
					}
				}
			}
		}

		return $this;
	}


    /**
     * Deny or allow a single or multiple roles by a single or multiple resources
     * @param string|array $roles A single role name or an array with role names
     * @param string|array $resources A single resource or an array with resources
     * @param bool $allowed True if resources may be access, false if not
     * @return self
     */
	private function fill($roles, $resources, $allowed): self {

	    $roles     = $this -> convertResource($roles);
	    $resources = $this -> convertResource($resources);

		foreach($roles as $role) {
			
			//Check if role already exists, if not create one
			$this -> roles[$role] ??= new Role($role);

			//Add the resources to the role
			$this -> roles[$role] -> addResources($resources, $allowed);
		}

		return $this;
	}


    /**
     * Converts given resource to an array if necessary and validates if given resource is a string or an array
     * @param string|array $resource The resource that needs to be validated and converted
     * @return array
     * @throws InvalidArgumentException
     */
	private function convertResource($resource): array {

        //Convert roles to array if roles is a string
        if(true === is_string($resource)) {
            $resource = [$resource];
        }

        //Check if roles is an array
        if(false === is_array($resource)) {
            throw new InvalidArgumentException(sprintf('Argument 1 passed to %s() must be of the type string or array, "%s" given', __METHOD__, gettype($resource)));
        }

        return $resource;
    }
}