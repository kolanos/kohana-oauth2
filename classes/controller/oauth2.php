<?php defined('SYSPATH') or die('No direct access allowed.');

class Controller_OAuth2 extends Controller {

	protected $oauth = NULL;
	
	public function before()
	{
		parent::before();

		$this->oauth = new OAuth2_Server_Database;
	}
	
}
