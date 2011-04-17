<?php

class Controller_OAuth2_Endpoint extends OAuth2_Server_Database {

	public function action_authorize()
	{
		if ($_POST)
		{
			$this->finish_client_authorization($_POST['accept'] == 'yes', $_POST);
		}

		$response_body = View::factory('oauth2/authorize');

		$response_body->oauth_params = $this->get_authorize_params();

		$this->response->body($response_body);
	}

	public function action_token()
	{
		$this->grant_access_token();
	}

}
