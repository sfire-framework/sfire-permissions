<?php
/**
 * sFire Framework (https://sfire.io)
 *
 * @link      https://github.com/sfire-framework/ for the canonical source repository
 * @copyright Copyright (c) 2014-2020 sFire Framework.
 * @license   http://sfire.io/license BSD 3-CLAUSE LICENSE
 */
 
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use sFire\Permissions\Acl\Acl;


final class AclTest extends TestCase {


    /**
     * Contains instance of Acl
     * @var Acl
     */
    private Acl $acl;
    

    /**
     * Setup. Created new Acl instance
     * @return void
     */
    protected function setUp(): void {
        $this -> acl = new Acl();
    }


    /**
     * Test if empty array is returned trying to retrieve all roles without adding roles
     * Test if non existing role is null after retrieving, without adding the role
     * @return void
     */
    public function testIfRolesAreReturned(): void {
        
        $this -> assertIsArray($this -> acl -> getRoles());
        $this -> assertEmpty($this -> acl -> getRoles());
        $this -> assertNull($this -> acl -> getRole('administrator'));
    }


    /**
     * Test if single role is added
     * Test if added role is of the correct type
     * @return void
     */
    public function testIfSingleRoleIsAdded(): void {

        $this -> acl -> addRole('administrator');
        $this -> assertIsArray($this -> acl -> getRoles());
        $this -> assertCount(1, $this -> acl -> getRoles());

        $role = $this -> acl -> getRole('administrator');
        $this -> assertInstanceOf('sFire\\Permissions\\Acl\\Role', $role);
    }


    /**
     * Test if multiple roles are added
     * Test if added roles are of the correct type
     * @return void
     */
    public function testIfMultipleRolesAreAdded(): void {

        $this -> acl -> addRoles(['administrator', 'moderator']);
        $this -> assertIsArray($this -> acl -> getRoles());
        $this -> assertCount(2, $this -> acl -> getRoles());

        $role = $this -> acl -> getRole('administrator');
        $this -> assertInstanceOf('sFire\\Permissions\\Acl\\Role', $role);

        $role = $this -> acl -> getRole('moderator');
        $this -> assertInstanceOf('sFire\\Permissions\\Acl\\Role', $role);
    }


    /**
     * Test if a existing role gets removed
     * @return void
     */
    public function testIfRolesAreRemoved(): void {

        $this -> assertFalse($this -> acl -> removeRole('administrator'));

        $this -> acl -> addRole('administrator');
        $this -> assertTrue($this -> acl -> removeRole('administrator'));
        $this -> assertNull($this -> acl -> getRole('administrator'));

        $this -> acl -> addRoles(['administrator', 'moderator']);
        $this -> assertTrue($this -> acl -> removeRole('administrator'));
        $this -> assertNull($this -> acl -> getRole('administrator'));

        $this -> acl -> allow('administrator', 'blog.edit');
        $this -> assertTrue($this -> acl -> removeRole('administrator'));
        $this -> assertNull($this -> acl -> getRole('administrator'));

        $this -> acl -> deny('administrator', 'blog.edit');
        $this -> assertTrue($this -> acl -> removeRole('administrator'));
        $this -> assertNull($this -> acl -> getRole('administrator'));
    }


    /**
     * Test if empty array is returned trying to retrieve all resources without adding resources
     * @return void
     */
    public function testIfResourcesAreReturned(): void {
        
        $this -> assertIsArray($this -> acl -> getResources());
        $this -> assertEmpty($this -> acl -> getResources());

        $this -> acl -> addRole('administrator', ['blog.edit', 'blog.create', 'blog.delete']);
        $this -> acl -> addRole('guest', ['blog.view']);

        $this -> assertIsArray($this -> acl -> getResources());
        $this -> assertCount(4, $this -> acl -> getResources());

        $resources = $this -> acl -> getRole('administrator') -> getResources();
        $this -> assertIsArray($resources);
        $this -> assertCount(3, $resources);
    }


    /**
     * Test if role is allowed to resource without setting roles and resources
     * @return void
     */
    public function testIsAllowedWithoutRolesAndResource(): void {
        $this -> assertFalse($this -> acl -> isAllowed('administrator', 'blog.edit'));
    }


    /**
     * Test if role is denied to resource without setting roles and resources
     * @return void
     */
    public function testIsDeniedWithoutRolesAndResource(): void {
        $this -> assertTrue($this -> acl -> isDenied('administrator', 'blog.edit'));
    }


    /**
     * Test if role is allowed to resource with setting roles and resources
     * Test if role is allowed to resource with setting roles and resources to deny first and then allowing
     * @return void
     */
    public function testIsAllowedWhenAllowed(): void {

        $roles      = ['administrator', 'moderator'];
        $resources  = ['blog.edit', 'blog.delete', 'blog.create', 'blog.view'];

        $this -> acl -> allow($roles, $resources);
        $this -> assertTrue($this -> acl -> isAllowed('administrator', 'blog.edit'));
        
        $this -> acl -> deny($roles, $resources);
        $this -> acl -> allow($roles, $resources);
        $this -> assertTrue($this -> acl -> isAllowed('administrator', 'blog.edit'));
    }


    /**
     * Test if role is denied to resource with setting roles and resources
     * Test if role is denied to resource with setting roles and resources to allow first and then denying
     * @return void
     */
    public function testIsDeniedWhenDenied(): void {

        $roles      = ['administrator', 'moderator'];
        $resources  = ['blog.edit', 'blog.delete', 'blog.create', 'blog.view'];

        $this -> acl -> deny($roles, $resources);
        $this -> assertTrue($this -> acl -> isDenied('administrator', 'blog.edit'));

        $this -> acl -> allow($roles, $resources);
        $this -> acl -> deny($roles, $resources);
        $this -> assertTrue($this -> acl -> isDenied('administrator', 'blog.edit'));
    }


    /**
     * Test if unknown role is allowed to known resource
     * Test if known role is allowed to unknown resource
     * Test if unknown role is allowed to unknown resource
     * @return void
     */
    public function testIsAllowedWithUnknownRoleAndResource(): void {

        $roles      = ['administrator', 'moderator'];
        $resources  = ['blog.edit', 'blog.delete', 'blog.create', 'blog.view'];

        $this -> acl -> allow($roles, $resources);

        $this -> assertFalse($this -> acl -> isAllowed('unknown', 'blog.edit'));
        $this -> assertFalse($this -> acl -> isAllowed('administrator', 'unknown'));
        $this -> assertFalse($this -> acl -> isAllowed('unknown', 'unknown'));
    }


    /**
     * Test if unknown role is denied to known resource
     * Test if known role is denied to unknown resource
     * Test if unknown role is denied to unknown resource
     * @return void
     */
    public function testIsDeniedWithUnknownRoleAndResource(): void {

        $roles      = ['administrator', 'moderator'];
        $resources  = ['blog.edit', 'blog.delete', 'blog.create', 'blog.view'];

        $this -> acl -> deny($roles, $resources);

        $this -> assertTrue($this -> acl -> isDenied('unknown', 'blog.edit'));
        $this -> assertTrue($this -> acl -> isDenied('administrator', 'unknown'));
        $this -> assertTrue($this -> acl -> isDenied('unknown', 'unknown'));
    }


    /**
     * Test if inheritance works on allowing resources
     * @return void
     */
    public function testIfAllowedInheritanceWorks(): void {

        $this -> acl -> allow('guest', 'blog.view');
        $this -> acl -> allow('administrator', ['blog.edit', 'blog.delete', 'blog.create']);
        $this -> acl -> inherit('administrator', 'guest');

        $this -> assertTrue($this -> acl -> isAllowed('administrator', 'blog.view'));
    }


    /**
     * Test if inheritance works on denying resources
     * @return void
     */
    public function testIfDeniedInheritanceWorks(): void {

        $this -> acl -> deny('guest', 'blog.view');
        $this -> acl -> deny('administrator', ['blog.edit', 'blog.delete', 'blog.create']);
        $this -> acl -> inherit('administrator', 'guest');

        $this -> assertTrue($this -> acl -> isDenied('administrator', 'blog.view'));
    }


    /**
     * Test if single role has resources after giving the role resources
     * Test if single role has the delete resource after giving the role the delete
     * Test if single role has the view resource without giving the role the view resource
     * @return void
     */
    public function testIfSingleRoleHasResources(): void {

        $this -> acl -> addRole('administrator');
        $this -> acl -> getRole('administrator') -> addResources(['blog.edit', 'blog.delete', 'blog.create']);
        $this -> assertIsArray($this -> acl -> getRole('administrator') -> getResources());
        $this -> assertCount(3, $this -> acl -> getRole('administrator') -> getResources());
        $this -> assertCount(1, $this -> acl -> getRole('administrator') -> getResources('delete'));
        $this -> assertCount(0, $this -> acl -> getRole('administrator') -> getResources('view'));
    }


    /**
     * Test if return type is null with removing resource from a single role without giving the role the resource
     * Test if return type is bool true with removing resource from a single role with giving the role the resource
     * Test if single role has the right resources after removing resources
     * @return void
     */
    public function testIfResourcesAreRemovedFromSingleRole(): void {

        $this -> acl -> addRole('administrator');
        $this -> assertNull($this -> acl -> getRole('administrator') -> removeResource('blog.create'));

        $this -> acl -> getRole('administrator') -> addResources(['blog.edit', 'blog.delete', 'blog.create']);
        $this -> assertTrue($this -> acl -> getRole('administrator') -> removeResource('blog.create'));
        
        $this -> assertIsArray($this -> acl -> getRole('administrator') -> getResources());
        $this -> assertCount(2, $this -> acl -> getRole('administrator') -> getResources());
        $this -> assertCount(1, $this -> acl -> getRole('administrator') -> getResources('delete'));
        $this -> assertCount(0, $this -> acl -> getRole('administrator') -> getResources('create'));
    }


    /**
     * Test if single role has the right resources
     * @return void
     */
    public function testIfSingleRoleHasResource(): void {

        $this -> acl -> addRole('administrator') -> addResources(['blog.edit', 'blog.delete', 'blog.create']);
        $this -> assertTrue($this -> acl -> getRole('administrator') -> hasResource('blog.delete'));
        $this -> assertFalse($this -> acl -> getRole('administrator') -> hasResource('blog.view'));
    }


    /**
     * Test if all resources are returned with corresponding roles
     * @return void
     */
    public function testAllResourcesWithRoles() {

        $this -> assertIsArray($this -> acl -> getResourcesWithRoles());
        $this -> assertCount(0, $this -> acl -> getResourcesWithRoles());

        $this -> acl -> addRole('guest', ['blog.view']);
        $this -> acl -> addRole('administrator') -> addResources(['blog.edit', 'blog.delete', 'blog.create']);
        $this -> acl -> inherit('administrator', 'guest');

        $this -> assertIsArray($this -> acl -> getResourcesWithRoles());
        $this -> assertCount(4, $this -> acl -> getResourcesWithRoles());
    }
}