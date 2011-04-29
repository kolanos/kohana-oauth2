<?php defined('SYSPATH') or die('No direct access allowed.');

class Controller_OAuth2_Endpoint extends Controller_OAuth2 {

	public function action_authorize()
	{
		if ($_POST)
		{
			$this->oauth->finish_client_authorization($_POST['accept'] == 'yes', $_POST);
		}

		$response_body = View::factory('oauth2/authorize');

		$response_body->oauth_params = $this->oauth->get_authorize_params();

		$this->response->body($response_body);
	}

	public function action_token()
	{
		$this->oauth->grant_access_token();
	}

}
