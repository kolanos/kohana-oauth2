<?php

Route::set('oauth2_endpoint', 'oauth2/<action>', array(
		'action' => '(authorize|token|return|debug)',
	))->defaults(array(
		'controller' => 'oauth2_endpoint',
	));

Route::set('oauth2_resource', 'oauth2/<controller>(/<action>(/<id>))')
	->defaults(array(
		'directory' => 'oauth2',
	));