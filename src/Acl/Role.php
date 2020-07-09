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

use sFire\Permissions\Exception\InvalidArgumentException;


/**
 * Class Role
 * @package sFire\Permissions\Acl
 */
class Role {


    /**
     * Contains the name of the role
     * @var string
     */
    private ?string $role;


    /**
     * Contains all the resources
     * @var array
     */
    private array $resources = [];


    /**
     * Constructor
     * @param string $role The role name
     */
    public function __construct(string $role) {
        $this -> role = $role;
    }


    /**
     * Returns the role name
     * @return null|string The role name
     */
    public function getRole(): ?string {
        return $this -> role;
    }


    /**
     * Sets the resources for current role
     * @param string|array $resources A single resource or an array of resources
     * @param bool $allowed True if resources are allowed to access, False if not
     * @return void
     * @throws InvalidArgumentException
     */
    public function addResources(array $resources, bool $allowed = true): void {

        if(true === is_string($resources)) {
            $resources = [$resources];
        }

        if(false === is_array($resources)) {
            throw new InvalidArgumentException(sprintf('Argument 1 passed to %s() must be of the type string or array, "%s" given', __METHOD__, gettype($resources)));
        }

        foreach($resources as $resource) {
            $this -> resources[$resource] = $allowed;
        }
    }


    /**
     * Removes a single resource from current role
     * @param string $resource The name of the resource
     * @return null|bool Null if resource could not be found, True if resource is successfully removed
     */
    public function removeResource(string $resource): ?bool {

        //Check if resource exists
        if(true === isset($this -> resources[$resource])) {

            unset($this -> resources[$resource]);
            return true;
        }

        return null;
    }


    /**
     * Retrieve all resources or all matched resources if $match is given as a Regex
     * @param null|string $match A Regex string to filter the resources on resource name
     * @return array Containing all the found resources
     */
    public function getResources(string $match = null): array {

        $resources = [];

        if(null === $match) {
            return $this -> resources;
        }

        foreach($this -> resources as $type => $value) {

            if(preg_match(sprintf('#%s#', str_replace('#', '\#', $match)), $type)) {
                $resources[] = $type;
            }
        }

        return $resources;
    }


    /**
     * Check if a resource exists
     * @param string $resource The name of the resource
     * @return bool True if resource exists, false if not
     */
    public function hasResource(string $resource): bool {
        return true === array_key_exists($resource, $this -> resources);
    }


    /**
     * Returns if a role is allowed access to the resource
     * @param string $resource The name of the resource
     * @return bool True if resource may be accessed, False if resource may not be accessed
     */
    public function isAllowed(string $resource): bool {

        if(true === isset($this -> resources[$resource])) {
            return $this -> resources[$resource];
        }

        return false;
    }


    /**
     * Returns if a role is denied access to the resource
     * @param string $resource
     * @return bool True if resource may not be accessed, False if resource may be accessed
     */
    public function isDenied(string $resource): bool {
        return !$this -> isAllowed($resource);
    }
}