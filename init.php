<?php

/*Route::set('oauth2_endpoint', 'oauth2/<action>', array(
		'action' => '(authorize|token|return|debug)',
	))->defaults(array(
		'controller' => 'oauth2_endpoint',
	));

Route::set('oauth2_resource', 'oauth2/<controller>(/<action>(/<id>))')
	->defaults(array(
		'directory' => 'oauth2',
	));*/
	
/** 
 * A replacement for apache_request_headers() for Nginx, Lighttpd and other web servers
 */
/*if ( ! function_exists('apache_request_headers'))
{
	function apache_request_headers()
	{
		foreach($_SERVER as $key => $value)
		{
			if (substr($key, 0, 5) == 'HTTP_')
			{
				$key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
				$out[$key] = $value;
			}
			else
			{
				$out[$key] = $value;
			}
		}

		return $out;
	}
}*/
