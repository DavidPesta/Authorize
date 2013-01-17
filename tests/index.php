<?php

/*
* Copyright (c) 2012-2013 David Pesta, http://www.simplemvc.org
* Licensed under the MIT License.
* You should have received a copy of the MIT License along with this program.
* If not, see http://www.opensource.org/licenses/mit-license.php
*/

include_once "../../simpletest/autorun.php";

class AllSimpleTests extends TestSuite {
	function __construct() {
		parent::__construct();
		$this->addFile( __DIR__ . "/AuthorizeTest.php" );
	}
}
