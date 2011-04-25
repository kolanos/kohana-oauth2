<?php defined('SYSPATH') or die('No direct access allowed.');

class Controller_OAuth2_Resource extends Controller_OAuth2 {

	protected function verify_access_token($scope = NULL, $exit_not_present = TRUE, $exit_invalid = TRUE, $exit_expired = TRUE, $exit_scope = TRUE, $realm = NULL)
	{
		return $this->oauth->verify_access_token($scope, $exit_not_present, $exit_invalid, $exit_expired, $exit_scope, $realm);
	}

}
