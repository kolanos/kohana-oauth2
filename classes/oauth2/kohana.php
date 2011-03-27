<?php

include_once Kohana::find_file('vendor', 'OAuth2');
include_once Kohana::find_file('vendor', 'OAuth2Exception');

class OAuth2_Kohana extends OAuth2 {
	
	protected function getSupportedScopes()
	{
		return array('testing1', 'testing2');
	}

	/**
	 * Implements OAuth2::checkClientCredentials().
	 */
	protected function checkClientCredentials($client_id, $client_secret = NULL)
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
	 * Implements OAuth2::getRedirectUri().
	 */
	protected function getRedirectUri($client_id)
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
	 * Implements OAuth2::getAccessToken().
	 */
	protected function getAccessToken($oauth_token)
	{
		Kohana::$log->add(Log::DEBUG, "Entering OAuth2_Kohana::getAccessToken.");

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
			Kohana::$log->add(Log::ERROR, "Unknown error in OAuth2_Kohana::getAccessToken. Message: " . $e->getMessage());

			return FALSE;
		}
	}

	/**
	 * Implements OAuth2::setAccessToken().
	 */
	protected function setAccessToken($oauth_token, $client_id, $expires, $scope = NULL)
	{
		Kohana::$log->add(Log::DEBUG, "Entering OAuth2_Kohana::setAccessToken.");

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
			Kohana::$log->add(Log::ERROR, "Unknown error in OAuth2_Kohana::setAccessToken. Message: " . $e->getMessage());

			return FALSE;
		}
	}

	/**
	 * Overrides OAuth2::getSupportedGrantTypes().
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
	protected function getSupportedGrantTypes()
	{
		Kohana::$log->add(Log::DEBUG, "Entering OAuth2_Kohana::getSupportedGrantTypes.");

		return array(
			OAUTH2_GRANT_TYPE_AUTH_CODE,
		);
	}

	/**
	 * Overrides OAuth2::getAuthCode().
	 */
	protected function getAuthCode($code)
	{
		Kohana::$log->add(Log::DEBUG, "Entering OAuth2_Kohana::getAuthCode.");

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
			Kohana::$log->add(Log::ERROR, "Unknown error in OAuth2_Kohana::getAuthCode. Message: " . $e->getMessage());

			return FALSE;
		}
	}

	/**
	 * Overrides OAuth2::setAuthCode().
	 */
	protected function setAuthCode($code, $client_id, $redirect_uri, $expires, $scope = NULL)
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