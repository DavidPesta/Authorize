<?php

/*
* Copyright (c) 2012-2013 David Pesta, https://github.com/DavidPesta/Authorize
* This file is licensed under the MIT License.
* You should have received a copy of the MIT License along with this program.
* If not, see http://www.opensource.org/licenses/mit-license.php
*/

class Authorize {
	protected $dbh;
	
	// Since priv names are tied into the codebase throughout the project's code, privs need to be defined
	// inside the code (not the database) in a numeric key based array and passed to the constructor
	protected $privs = [];
	
	// For various method executions that fetch from the database, cache the results inside of these properties so that the database doesn't get hit more than once
	protected $userIds = [];
	protected $usernames = [];
	protected $roleIds = [];
	protected $rolenames = [];
	protected $roles = null;
	protected $userRoles = [];
	protected $userPrivs = [];
	protected $rolePrivs = [];
	protected $roleUsers = [];
	protected $privUsers = [];
	protected $privRoles = [];
	
	public function __construct( & $dbh, $privs ) {
		if( get_class( $dbh ) != "DatabaseHandler" ) throw new Exception( "An instance of DatabaseHandler must be passed to the Authorize constructor" );
		$this->dbh =& $dbh;
		$this->privs = $privs;
	}
	
	public function clearCache() {
		$this->userIds = [];
		$this->usernames = [];
		$this->roleIds = [];
		$this->rolenames = [];
		$this->roles = null;
		$this->userRoles = [];
		$this->userPrivs = [];
		$this->rolePrivs = [];
		$this->roleUsers = [];
		$this->privUsers = [];
		$this->privRoles = [];
	}
	
	// Check if the user has this priv; priv based authorization using this function is the best practice
	// Returns: true/false
	public function priv( $priv, $user = null ) {
		if( $user == null ) $user = $_SESSION[ 'userId' ];
		
		if( is_numeric( $user ) ) $userId = $user;
		else $userId = $this->fetchUserId( $user );
		
		$userPrivs = $this->fetchUserPrivs( $userId );
		
		if( in_array( $priv, $userPrivs ) ) return true;
		else return false;
	}
	
	// Check if the user has this role; using this is not a best practice; use priv above instead
	// Returns: true/false
	public function role( $role, $user = null ) {
		if( $user == null ) $user = $_SESSION[ 'userId' ];
		
		if( is_numeric( $user ) ) $userId = $user;
		else $userId = $this->fetchUserId( $user );
		
		$userRoles = $this->fetchUserRoles( $userId );
		
		if( in_array( $role, $userRoles ) ) return true;
		else return false;
	}
	
	// Check if the user IS this user; for unusual use cases, not to be used in typical situations
	// Returns: true/false
	public function user( $user1, $user2 = null ) {
		if( $user2 == null ) $user2 = $_SESSION[ 'userId' ];
		
		if( is_numeric( $user2 ) ) $user2Id = $user2;
		else $user2Id = $this->fetchUserId( $user2 );
		
		if( is_numeric( $user1 ) ) $user1Id = $user1;
		else $user1Id = $this->fetchUserId( $user1 );
		
		if( $user1Id == $user2Id ) return true;
		else return false;
	}
	
	public function addUserRole( $user, $role ) {
		if( is_numeric( $user ) ) $userId = $user;
		else $userId = $this->fetchUserId( $user );
		
		if( is_numeric( $role ) ) $roleId = $role;
		else $roleId = $this->fetchRoleId( $role );
		
		$this->dbh->insert( "user_roles", [ $userId, $roleId ] );
		
		$this->clearCache();
	}
	
	public function addRolePriv( $role, $priv ) {
		if( is_numeric( $role ) ) $roleId = $role;
		else $roleId = $this->fetchRoleId( $role );
		
		if( is_numeric( $priv ) ) $privId = $priv;
		else $privId = array_search( $priv, $this->privs );
		
		$this->dbh->insert( "role_privs", [ $roleId, $privId ] );
		
		$this->clearCache();
	}
	
	public function addUserPriv( $user, $priv ) {
		if( is_numeric( $user ) ) $userId = $user;
		else $userId = $this->fetchUserId( $user );
		
		if( is_numeric( $priv ) ) $privId = $priv;
		else $privId = array_search( $priv, $this->privs );
		
		$this->dbh->insert( "user_privs", [ $userId, $privId ] );
		
		$this->clearCache();
	}
	
	public function removeUserRole( $user, $role ) {
		if( is_numeric( $user ) ) $userId = $user;
		else $userId = $this->fetchUserId( $user );
		
		if( is_numeric( $role ) ) $roleId = $role;
		else $roleId = $this->fetchRoleId( $role );
		
		$this->dbh->delete( "user_roles", [ $userId, $roleId ] );
		
		$this->clearCache();
	}
	
	public function removeRolePriv( $role, $priv ) {
		if( is_numeric( $role ) ) $roleId = $role;
		else $roleId = $this->fetchRoleId( $role );
		
		if( is_numeric( $priv ) ) $privId = $priv;
		else $privId = array_search( $priv, $this->privs );
		
		$this->dbh->delete( "role_privs", [ $roleId, $privId ] );
		
		$this->clearCache();
	}
	
	public function removeUserPriv( $user, $priv ) {
		if( is_numeric( $user ) ) $userId = $user;
		else $userId = $this->fetchUserId( $user );
		
		if( is_numeric( $priv ) ) $privId = $priv;
		else $privId = array_search( $priv, $this->privs );
		
		$this->dbh->delete( "user_privs", [ $userId, $privId ] );
		
		$this->clearCache();
	}
	
	// Returns: userId
	public function fetchUserId( $username ) {
		if( isset( $this->userIds[ $username ] ) ) return $this->userIds[ $username ];
		return $this->userIds[ $username ] = $this->dbh->fetchValue( "select userId from users where username = ?", $username );
	}
	
	// Returns: username
	public function fetchUsername( $userId = null ) {
		if( $userId == null ) $userId = $_SESSION[ 'userId' ];
		if( isset( $this->usernames[ $userId ] ) ) return $this->usernames[ $userId ];
		return $this->usernames[ $userId ] = $this->dbh->fetchValue( "select username from users where userId = ?", $userId );
	}
	
	// Returns: roleId
	public function fetchRoleId( $rolename ) {
		if( isset( $this->roleIds[ $rolename ] ) ) return $this->roleIds[ $rolename ];
		return $this->roleIds[ $rolename ] = $this->dbh->fetchValue( "select roleId from roles where rolename = ?", $rolename );
	}
	
	// Returns: rolename
	public function fetchRolename( $roleId ) {
		if( isset( $this->rolenames[ $roleId ] ) ) return $this->rolenames[ $roleId ];
		return $this->rolenames[ $roleId ] = $this->dbh->fetchValue( "select rolename from roles where roleId = ?", $roleId );
	}
	
	// Returns: privId
	public function fetchPrivId( $priv ) {
		return array_search( $priv, $this->privs );
	}
	
	// Returns: priv name
	public function fetchPriv( $privId ) {
		return $this->privs[ $privId ];
	}
	
	// Returns: [ roleId => rolename ]
	public function fetchRoles() {
		if( ! is_null( $this->roles ) ) return $this->roles;
		return $this->roles = $this->dbh->fetchGroup( "roleId", "rolename", "select distinct( roleId ), rolename from roles" );
	}
	
	// Returns: [ privId => priv name ]
	public function fetchPrivs() {
		return $this->privs;
	}
	
	// Returns: [ roleId => rolename ]
	public function fetchUserRoles( $user ) {
		if( is_numeric( $user ) ) $userId = $user;
		else $userId = $this->fetchUserId( $user );
		
		if( isset( $this->userRoles[ $userId ] ) ) return $this->userRoles[ $userId ];
		
		return $this->userRoles[ $userId ] = $this->dbh->fetchGroup( "roleId", "rolename", "
			select
				distinct( r.roleId ),
				r.rolename
			from
				user_roles ur
			join
				roles r on ur.roleId = r.roleId
			where
				userId = ?
		", $userId );
	}
	
	// Combines the user_privs and the joined role_privs
	// Returns: [ privId => priv names ]
	public function fetchUserPrivs( $user ) {
		if( is_numeric( $user ) ) $userId = $user;
		else $userId = $this->fetchUserId( $user );
		
		if( isset( $this->userPrivs[ $userId ] ) ) return $this->userPrivs[ $userId ];
		
		// Fetch the privs from the user's roles
		$rolePrivs = $this->dbh->fetchGroup( null, "privId", "
			select
				privId
			from
				user_roles ur
			join
				role_privs rp on ur.roleId = rp.roleId
			where
				userId = ?
		", $userId );
		
		// Fetch the ad-hoc user privs
		$userPrivs = $this->dbh->fetchGroup( null, "privId", "select privId from user_privs where userId = ?", $userId );
		
		$allPrivs = array_unique( array_merge( $rolePrivs, $userPrivs ) );
		
		$privs = array();
		foreach( $allPrivs as $privId ) {
			$privs[ $privId ] = $this->privs[ $privId ];
		}
		
		return $this->userPrivs[ $userId ] = $privs;
	}
	
	// Returns: [ privId => priv name ]
	public function fetchRolePrivs( $role ) {
		if( is_numeric( $role ) ) $roleId = $role;
		else $roleId = $this->fetchRoleId( $role );
		
		if( isset( $this->rolePrivs[ $roleId ] ) ) return $this->rolePrivs[ $roleId ];
		
		$rolePrivIds = $this->dbh->fetchGroup( null, "privId", "select privId from role_privs where roleId = ?", $roleId );
		
		$rolePrivs = array();
		foreach( $rolePrivIds as $privId ) {
			$rolePrivs[ $privId ] = $this->privs[ $privId ];
		}
		
		return $this->rolePrivs[ $roleId ] = $rolePrivs;
	}
	
	// Returns: [ userId => username ]
	public function fetchRoleUsers( $role ) {
		if( is_numeric( $role ) ) $roleId = $role;
		else $roleId = $this->fetchRoleId( $role );
		
		if( isset( $this->roleUsers[ $roleId ] ) ) return $this->roleUsers[ $roleId ];
		
		return $this->roleUsers[ $roleId ] = $this->dbh->fetchGroup( "userId", "username", "
			select
				distinct( u.userId ),
				u.username
			from
				user_roles ur
			join
				users u on ur.userId = u.userId
			where
				ur.roleId = ?
		", $roleId );
	}
	
	// Returns: [ userId => username ]
	public function fetchPrivUsers( $priv ) {
		if( is_numeric( $priv ) ) $privId = $priv;
		else $privId = array_search( $priv, $this->privs );
		
		if( isset( $this->privUsers[ $privId ] ) ) return $this->privUsers[ $privId ];
		
		$rolePrivUsers = $this->dbh->fetchGroup( "userId", "username", "
			select
				distinct( u.userId ),
				u.username
			from
				role_privs rp
			join
				user_roles ur on rp.roleId = ur.roleId
			join
				users u on ur.userId = u.userId
			where
				rp.privId = ?
		", $privId );
		
		$userPrivUsers = $this->dbh->fetchGroup( "userId", "username", "
			select
				distinct( u.userId ),
				u.username
			from
				user_privs up
			join
				users u on up.userId = u.userId
			where
				up.privId = ?
		", $privId );
		
		return $this->privUsers[ $privId ] = $rolePrivUsers + $userPrivUsers;
	}
	
	// Returns: [ roleId => rolename ]
	public function fetchPrivRoles( $priv ) {
		if( is_numeric( $priv ) ) $privId = $priv;
		else $privId = array_search( $priv, $this->privs );
		
		if( isset( $this->privRoles[ $privId ] ) ) return $this->privRoles[ $privId ];
		
		return $this->privRoles[ $privId ] = $this->dbh->fetchGroup( "roleId", "rolename", "
			select
				distinct( r.roleId ),
				r.rolename
			from
				role_privs rp
			join
				roles r on rp.roleId = r.roleId
			where
				rp.privId = ?
		", $privId );
	}
}
