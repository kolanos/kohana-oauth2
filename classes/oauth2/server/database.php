<?php

class OAuth2_Server_Database extends OAuth2_Server {
	
	protected function get_supported_scopes()
	{
		return array('testing1', 'testing2');
	}

	/**
	 * Implements OAuth2::check_client_credentials().
	 */
	protected function check_client_credentials($client_id, $client_secret = NULL)
	{
		Kohana::$log->add(Log::DEBUG, "Entering OAuth2_Kohana::checkClientCredentials.");

		try
		{
			$result = DB::query(Database::SELECT, 'SELECT client_secret FROM oauth2_clients WHERE client_id = :client_id')
			          ->param(':client_id', $client_id)
			          ->execute();

			// Ensure we have no more or less than 1 result.
			if (count($result) != 1)
				return FALSE;

			// Since we only have one result ..
			$result = current($result)->as_array();

			if ($client_secret === NULL)
				return $result !== FALSE;

			return $result["client_secret"] == $client_secret;
		}
		catch (Database_Exception $e)
		{
			Kohana::$log->add(Log::ERROR, "Unknown error in OAuth2_Kohana::checkClientCredentials. Message: " . $e->getMessage());

			return FALSE;
		}
	}

	/**
	 * Implements OAuth2::get_redirect_uri().
	 */
	protected function get_redirect_uri($client_id)
	{
		Kohana::$log->add(Log::DEBUG, "Entering OAuth2_Kohana::getRedirectUri.");

		try
		{
			$result = DB::query(Database::SELECT, 'SELECT redirect_uri FROM oauth2_clients WHERE client_id = :client_id')
			          ->param(':client_id', $client_id)
				      ->execute()->as_array();

			// Ensure we have no more or less than 1 result.
			if (count($result) != 1)
				return FALSE;

			// Since we only have one result ..
			$result = current($result);

			return isset($result["redirect_uri"]) && $result["redirect_uri"] ? $result["redirect_uri"] : NULL;
		}
		catch (Database_Exception $e)
		{
			Kohana::$log->add(Log::ERROR, "Unknown error in OAuth2_Kohana::getRedirectUri. Message: " . $e->getMessage());

			return FALSE;
		}
	}

	/**
	 * Implements OAuth2::get_access_token().
	 */
	protected function get_access_token($oauth_token)
	{
		Kohana::$log->add(Log::DEBUG, "Entering OAuth2_Kohana::get_access_token.");

		try
		{
			$result = DB::query(Database::SELECT, 'SELECT client_id, expires, scope FROM oauth2_tokens WHERE oauth_token = :oauth_token')
			          ->param(':oauth_token', $oauth_token)
			          ->execute();

			// Ensure we have no more or less than 1 result.
			if (count($result) != 1)
				return FALSE;

			// Since we only have one result .. 
			$result = current($result)->as_array();

			return $result !== FALSE ? $result : NULL;
		}
		catch (Database_Exception $e)
		{
			Kohana::$log->add(Log::ERROR, "Unknown error in OAuth2_Kohana::get_access_token. Message: " . $e->getMessage());

			return FALSE;
		}
	}

	/**
	 * Implements OAuth2::set_access_token().
	 */
	protected function set_access_token($oauth_token, $client_id, $expires, $scope = NULL)
	{
		Kohana::$log->add(Log::DEBUG, "Entering OAuth2_Kohana::set_access_token.");

		try
		{
			$result = DB::query(Database::INSERT, 'INSERT INTO oauth2_tokens (oauth_token, client_id, expires, scope) VALUES (:oauth_token, :client_id, :expires, :scope)')
						->parameters(array(
							':oauth_token' => $oauth_token,
							':client_id' => $client_id,
							':expires' => $expires,
							':scope' => $scope,
						))->execute();
		}
		catch (Database_Exception $e)
		{
			Kohana::$log->add(Log::ERROR, "Unknown error in OAuth2_Kohana::set_access_token. Message: " . $e->getMessage());

			return FALSE;
		}
	}

	/**
	 * Overrides OAuth2::get_supported_grant_types().
	 * 
	 * Possible values:
	 *
	 * return array(
	 *   OAUTH2_GRANT_TYPE_AUTH_CODE,
	 *   OAUTH2_GRANT_TYPE_USER_CREDENTIALS,
	 *   OAUTH2_GRANT_TYPE_ASSERTION,
	 *   OAUTH2_GRANT_TYPE_REFRESH_TOKEN,
	 *   OAUTH2_GRANT_TYPE_NONE,
	 * );
	 *
	 * See http://tools.ietf.org/html/draft-ietf-oauth-v2-13 Section 1.4
	 */
	protected function get_supported_grant_types()
	{
		Kohana::$log->add(Log::DEBUG, "Entering OAuth2_Kohana::get_supported_grant_types.");

		return array(
			OAUTH2_GRANT_TYPE_AUTH_CODE,
		);
	}

	/**
	 * Overrides OAuth2::get_auth_code().
	 */
	protected function get_auth_code($code)
	{
		Kohana::$log->add(Log::DEBUG, "Entering OAuth2_Kohana::get_auth_code.");

		try
		{
			$result = DB::query(Database::SELECT, 'SELECT code, client_id, redirect_uri, expires, scope FROM oauth2_auth_codes WHERE code = :code')
			          ->param(':code', $code)
			          ->execute();

			// Ensure we have no more or less than 1 result.
			if (count($result) != 1)
				return FALSE;

			// Since we only have one result ..
			$result = current($result)->as_array();

			return $result !== FALSE ? $result : NULL;
		}
		catch (Database_Exception $e)
		{
			Kohana::$log->add(Log::ERROR, "Unknown error in OAuth2_Kohana::get_auth_code. Message: " . $e->getMessage());

			return FALSE;
		}
	}

	/**
	 * Overrides OAuth2::set_auth_code().
	 */
	protected function set_auth_code($code, $client_id, $redirect_uri, $expires, $scope = NULL)
	{
		Kohana::$log->add(Log::DEBUG, "Entering OAuth2_Kohana::setAuthCode.");

		try
		{
			$result = DB::query(Database::INSERT, 'INSERT INTO oauth2_auth_codes (code, client_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :redirect_uri, :expires, :scope)')
						->parameters(array(
							':code' => $code,
							':client_id' => $client_id,
							':redirect_uri' => $redirect_uri,
							':expires' => $expires,
							':scope' => $scope,
						))->execute();
		}
		catch (Database_Exception $e)
		{
			Kohana::$log->add(Log::ERROR, "Unknown error in OAuth2_Kohana::setAuthCode. Message: " . $e->getMessage());

			return FALSE;
		}
	}
	
}
