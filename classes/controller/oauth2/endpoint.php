<?php

class Controller_OAuth2_Endpoint extends Controller_OAuth2 {

	public function action_authorize()
	{
		if ($_POST)
		{
			$this->oauth->finishClientAuthorization($_POST["accept"] == "yes", $_POST);
		}

		$response_body = View::factory('oauth2/authorize');

		$response_body->oauth_params = $this->oauth->getAuthorizeParams();

		$this->response->body($response_body);
	}

	public function action_token()
	{
		$this->oauth->grantAccessToken();
	}
}