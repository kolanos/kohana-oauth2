<?php

include_once Kohana::find_file('vendor', 'OAuth2Client');
include_once Kohana::find_file('vendor', 'OAuth2Exception');

class OAuth2_Test extends OAuth2Client {
	protected $config = array(
		'base_uri' => 'http://wk01-lmst.managedit.ie/oauth2-php/server/examples/pdo/',
		'authorize_uri' => 'authorize.php',
		'access_token_uri' => 'token.php',
		'client_id' => '0123456789ab',
		'client_secret' => 'hello  world',
		'cookie_support' => TRUE,
	);

	public function __construct($config = array())
	{
		$config = $this->config + $config;

		parent::__construct($config);
	}

	/**
	 * Get a Login URL for use with redirects. By default, full page redirect is
	 * assumed. If you are using the generated URL with a window.open() call in
	 * JavaScript, you can pass in display = popup as part of the $params.
	 *
	 * @param $params
	 *   Provide custom parameters.
	 *
	 * @return
	 *   The URL for the login flow.
	 */
	public function getAuthorizeUrl($params = array())
	{
		return $this->getUri(
			$this->getVariable('authorize_uri'),
			array_merge(array(
				'response_type' => 'code',
				'client_id' => $this->getVariable('client_id'),
				'redirect_uri' => $this->getCurrentUri(),
				), $params)
		);
	}
}