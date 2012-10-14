<?php

/*
* Copyright (c) 2012 David Pesta, https://github.com/DavidPesta/Authorize
* This file is licensed under the MIT License.
* You should have received a copy of the MIT License along with this program.
* If not, see http://www.opensource.org/licenses/mit-license.php
*/

include_once "../../SimpleTest/autorun.php";
include_once "../database/DatabaseHandler.php";
include_once "../Authorize.php";

class AuthorizeTest extends UnitTestCase {
	private $dbh;
	private $authorize;
	
	function setUp() {
		ini_set( "max_execution_time", 900 );
		
		// Create database, tables, and data for the test
		$this->dbh = new DatabaseHandler();
		$this->dbh->createDatabase( "authorizetest" );
		$this->dbh->createTables( file_get_contents( "../database/authorize.sql" ) );
		
		// An appropriate place to define these is generally where Authorize is instantiated to create the object, like a bootstrap or a small include
		$privs = [
			1 => "1st Admin Priv",
			2 => "2nd Admin Priv",
			3 => "1st Member Priv",
			4 => "2nd Member Priv"
		];
		
		$this->authorize = new Authorize( $this->dbh, $privs );
		
		$users = [ "David", "Mike", "Rick" ];
		$roles = [ "Admin", "Member" ];
		
		foreach( $users as $user ) $this->dbh->insert( "users", [ null, $user ] );
		foreach( $roles as $role ) $this->dbh->insert( "roles", [ null, $role ] );
		
		$this->authorize->addUserRole( "David", "Admin" );
		$this->authorize->addUserRole( "David", "Member" );
		$this->authorize->addUserRole( "Mike", "Member" );
		
		$this->authorize->addRolePriv( "Admin", "1st Admin Priv" );
		$this->authorize->addRolePriv( "Admin", "2nd Admin Priv" );
		$this->authorize->addRolePriv( "Member", "1st Member Priv" );
		$this->authorize->addRolePriv( "Member", "2nd Member Priv" );

		$this->authorize->addUserPriv( "Mike", "1st Admin Priv" );
		$this->authorize->addUserPriv( "Rick", "2nd Admin Priv" );
		$this->authorize->addUserPriv( "David", "2nd Admin Priv" ); // This shows that redundancy of adding user privs when they already have role privs isn't a problem
	}
	
	function testConstructorRequiresDatabaseHandler() {
		$this->expectException(new PatternExpectation("/An instance of DatabaseHandler must be passed to the Authorize constructor/"));
		$authorize = new Authorize( new stdClass, [] );
	}
	
	function testClearCache() {
		$this->dbh->insert( "users", [ null, "Nelson" ] );
		
		$userId = $this->authorize->fetchUserId( "Nelson" );
		$this->AssertNotNull( $userId );
		
		$this->dbh->delete( "users", [ $userId ] );
		
		$userId = $this->authorize->fetchUserId( "Nelson" );
		$this->AssertNotNull( $userId );
		
		$this->authorize->clearCache();
		
		$userId = $this->authorize->fetchUserId( "Nelson" );
		$this->AssertNull( $userId );
	}
	
	function testPriv() {
		$this->AssertTrue( $this->authorize->priv( '1st Admin Priv', "David" ) );
		$this->AssertTrue( $this->authorize->priv( '2nd Admin Priv', "David" ) );
		$this->AssertTrue( $this->authorize->priv( '1st Member Priv', "David" ) );
		$this->AssertTrue( $this->authorize->priv( '2nd Member Priv', "David" ) );
		
		$this->AssertTrue( $this->authorize->priv( '1st Admin Priv', "Mike" ) );
		$this->AssertFalse( $this->authorize->priv( '2nd Admin Priv', "Mike" ) );
		$this->AssertTrue( $this->authorize->priv( '1st Member Priv', "Mike" ) );
		$this->AssertTrue( $this->authorize->priv( '2nd Member Priv', "Mike" ) );
		
		$this->AssertFalse( $this->authorize->priv( '1st Admin Priv', "Rick" ) );
		$this->AssertTrue( $this->authorize->priv( '2nd Admin Priv', "Rick" ) );
		$this->AssertFalse( $this->authorize->priv( '1st Member Priv', "Rick" ) );
		$this->AssertFalse( $this->authorize->priv( '2nd Member Priv', "Rick" ) );
	}
	
	function testRole() {
		$this->AssertTrue( $this->authorize->role( "Admin", "David" ) );
		$this->AssertTrue( $this->authorize->role( "Member", "David" ) );

		$this->AssertFalse( $this->authorize->role( "Admin", "Mike" ) );
		$this->AssertTrue( $this->authorize->role( "Member", "Mike" ) );

		$this->AssertFalse( $this->authorize->role( "Admin", "Rick" ) );
		$this->AssertFalse( $this->authorize->role( "Member", "Rick" ) );
	}
	
	function testUser() {
		$this->AssertTrue( $this->authorize->user( "David", "David" ) );
		$this->AssertTrue( $this->authorize->user( "Mike", "Mike" ) );
		$this->AssertTrue( $this->authorize->user( "Rick", "Rick" ) );
		
		$this->AssertFalse( $this->authorize->user( "David", "Mike" ) );
		$this->AssertFalse( $this->authorize->user( "David", "Rick" ) );
		$this->AssertFalse( $this->authorize->user( "Mike", "Rick" ) );
	}
	
	function testRemoveUserRole() {
		$this->AssertTrue( $this->authorize->role( "Admin", "David" ) );
		
		$this->authorize->removeUserRole( "David", "Admin" );
		
		$this->AssertFalse( $this->authorize->role( "Admin", "David" ) );
	}
	
	function testRemoveRolePriv() {
		$rolePrivs = $this->authorize->fetchRolePrivs( "Admin" );
		$this->AssertTrue( in_array( "1st Admin Priv", $rolePrivs ) );
		
		$this->authorize->removeRolePriv( "Admin", "1st Admin Priv" );
		
		$rolePrivs = $this->authorize->fetchRolePrivs( "Admin" );
		$this->AssertFalse( in_array( "1st Admin Priv", $rolePrivs ) );
	}
	
	function testRemoveUserPriv() {
		$this->AssertTrue( $this->authorize->priv( "2nd Admin Priv", "Rick" ) );
		
		$this->authorize->removeUserPriv( "Rick", "2nd Admin Priv" );
		
		$this->AssertFalse( $this->authorize->priv( "2nd Admin Priv", "Rick" ) );
	}
	
	function testFetchUserIdAndFetchUsername() {
		$userId = $this->authorize->fetchUserId( "David" );
		$username = $this->authorize->fetchUsername( $userId );
		$this->assertEqual( "David", $username );
	}
	
	function testFetchRoleIdAndRolename() {
		$roleId = $this->authorize->fetchRoleId( "Admin" );
		$rolename = $this->authorize->fetchRolename( $roleId );
		$this->assertEqual( "Admin", $rolename );
	}
	
	function testFetchPrivIdAndFetchPriv() {
		$privId = $this->authorize->fetchPrivId( "2nd Admin Priv" );
		$priv = $this->authorize->fetchPriv( $privId );
		$this->assertEqual( "2nd Admin Priv", $priv );
	}
	
	function testFetchRoles() {
		$roles = $this->authorize->fetchRoles();
		$testRoles = [
			1 => "Admin",
			2 => "Member"
		];
		$this->assertEqual( $testRoles, $roles );
	}
	
	function testFetchPrivs() {
		$privs = $this->authorize->fetchPrivs();
		$testPrivs = [
			1 => "1st Admin Priv",
			2 => "2nd Admin Priv",
			3 => "1st Member Priv",
			4 => "2nd Member Priv"
		];
		$this->assertEqual( $testPrivs, $privs );
	}
	
	function testFetchUserRoles() {
		$userRoles = $this->authorize->fetchUserRoles( "David" );
		$testUserRoles = [
			1 => "Admin",
			2 => "Member"
		];
		$this->assertEqual( $testUserRoles, $userRoles );
	}
	
	function testFetchUserPrivs() {
		$userPrivs = $this->authorize->fetchUserPrivs( "Mike" );
		$testUserPrivs = [
			3 => "1st Member Priv",
    		4 => "2nd Member Priv",
    		1 => "1st Admin Priv"
		];
		$this->assertEqual( $testUserPrivs, $userPrivs );
	}
	
	function testFetchRolePrivs() {
		$rolePrivs = $this->authorize->fetchRolePrivs( "Admin" );
		$testRolePrivs = [
			1 => "1st Admin Priv",
    		2 => "2nd Admin Priv"
		];
		$this->assertEqual( $testRolePrivs, $rolePrivs );
		
		$rolePrivs = $this->authorize->fetchRolePrivs( "Member" );
		$testRolePrivs = [
			3 => "1st Member Priv",
    		4 => "2nd Member Priv"
		];
		$this->assertEqual( $testRolePrivs, $rolePrivs );
	}
	
	function testFetchRoleUsers() {
		$roleUsers = $this->authorize->fetchRoleUsers( "Admin" );
		$testRoleUsers = [
			1 => "David"
		];
		$this->assertEqual( $testRoleUsers, $roleUsers );
		
		$roleUsers = $this->authorize->fetchRoleUsers( "Member" );
		$testRoleUsers = [
			1 => "David",
    		2 => "Mike"
		];
		$this->assertEqual( $testRoleUsers, $roleUsers );
	}
	
	function testFetchPrivUsers() {
		$privUsers = $this->authorize->fetchPrivUsers( "2nd Admin Priv" );
		$testPrivUsers = [
			1 => "David",
    		3 => "Rick"
		];
		$this->assertEqual( $testPrivUsers, $privUsers );
		
		$privUsers = $this->authorize->fetchPrivUsers( "1st Admin Priv" );
		$testPrivUsers = [
			1 => "David",
    		2 => "Mike"
		];
		$this->assertEqual( $testPrivUsers, $privUsers );
		
		$privUsers = $this->authorize->fetchPrivUsers( "1st Member Priv" );
		$testPrivUsers = [
			1 => "David",
    		2 => "Mike"
		];
		$this->assertEqual( $testPrivUsers, $privUsers );
	}
	
	function testFetchPrivRoles() {
		$privRoles = $this->authorize->fetchPrivRoles( "1st Admin Priv" );
		$testPrivRoles = [
			1 => "Admin"
		];
		$this->assertEqual( $testPrivRoles, $privRoles );
		
		$privRoles = $this->authorize->fetchPrivRoles( "2nd Member Priv" );
		$testPrivRoles = [
			2 => "Member"
		];
		$this->assertEqual( $testPrivRoles, $privRoles );
		
		$this->authorize->addRolePriv( "Member", "1st Admin Priv" );
		
		$privRoles = $this->authorize->fetchPrivRoles( "1st Admin Priv" );
		$testPrivRoles = [
			1 => "Admin",
    		2 => "Member"
		];
		$this->assertEqual( $testPrivRoles, $privRoles );
	}
	
	function testOverlappingRolePrivs() {
		$privs = [
			1 => "1st Admin Priv",
			2 => "2nd Admin Priv",
			3 => "1st Member Priv",
			4 => "2nd Member Priv",
			5 => "Overlapping Priv"
		];
		
		$this->authorize = new Authorize( $this->dbh, $privs );

		$this->authorize->addRolePriv( "Admin", "Overlapping Priv" );
		$this->authorize->addRolePriv( "Member", "Overlapping Priv" );
		
		$this->AssertTrue( $this->authorize->priv( 'Overlapping Priv', "David" ) );
		
		$userPrivs = $this->authorize->fetchUserPrivs( "David" );
		$testUserPrivs = [
			1 => "1st Admin Priv",
			2 => "2nd Admin Priv",
			3 => "1st Member Priv",
			4 => "2nd Member Priv",
			5 => "Overlapping Priv"
		];
		$this->assertEqual( $testUserPrivs, $userPrivs );
		
		$rolePrivs = $this->authorize->fetchRolePrivs( "Admin" );
		$testRolePrivs = [
			1 => "1st Admin Priv",
    		2 => "2nd Admin Priv",
    		5 => "Overlapping Priv"
		];
		$this->assertEqual( $testRolePrivs, $rolePrivs );
		
		$rolePrivs = $this->authorize->fetchRolePrivs( "Member" );
		$testRolePrivs = [
			3 => "1st Member Priv",
    		4 => "2nd Member Priv",
    		5 => "Overlapping Priv"
		];
		$this->assertEqual( $testRolePrivs, $rolePrivs );
		
		$privUsers = $this->authorize->fetchPrivUsers( "Overlapping Priv" );
		$testPrivUsers = [
			1 => "David",
    		2 => "Mike"
		];
		$this->assertEqual( $testPrivUsers, $privUsers );
		
		$privRoles = $this->authorize->fetchPrivRoles( "Overlapping Priv" );
		$testPrivRoles = [
			1 => "Admin",
    		2 => "Member"
		];
		$this->assertEqual( $testPrivRoles, $privRoles );
	}
	
	function tearDown() {
		// Drop test database
		$this->dbh->dropDatabase();
		
		// Close the PDO connection
		$this->dbh = null;
	}
}
