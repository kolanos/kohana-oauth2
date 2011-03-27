<?php
/**
 * Example OAuth 2 Client
 */
class Controller_OTest extends Controller
{

	/**
	 * OAuth2 Test Client
	 * 
	 * @var OAuth2_Test 
	 */
	protected $test_client;

	/**
	 * Lets setup the client .. 
	 */
	public function before()
	{
		$this->test_client = new OAuth2_Test();
	}

	/**
	 * This is where users get redirected back to after allowing (or disallowing) access.
	 */
//	public function action_return()
//	{
//		if (isset($_GET['code']))
//		{
//			$this->test_client->setVariable('code', $_GET['code']);
//
//			$session = $this->test_client->getSession();
//
//			if ($session)
//			{
//				$this->request->redirect($_GET['state']);
//			}
//		}
//
//		echo "<h1>Error</h1>";
//
//		var_dump($_GET);
//	}

	/**
	 * Here, we want to use some protected data from the OAuth2 based API .. 
	 */
	public function action_index()
	{

		try
		{
			$protected_data = $this->test_client->api('/protected_resource.php');

			echo Debug::vars($protected_data);
		}
		catch (OAuth2Exception $e)
		{
			if (isset($_GET['error']))
			{

			}


			if ($e->getCode() == 401)
			{
				if ($_GET['error'])
				{
					
				}
				else
				{
					$this->request->redirect($this->test_client->getAuthorizeUrl());
				}
			}
			else
			{
				throw $e;
			}
//			switch ($e->getCode())
//			{
//				// Authorization Required
//				case 401:
//
//					$this->request->redirect($this->test_client->getAuthorizeUrl());
//					break;
//				// Unknown error .. rethrow
//				default:
//					throw $e;
//					break;
//			}
			echo Debug::vars($e);

			echo $this->test_client->getAuthorizeUrl();
			// Lets get their permission ..
//			
		}
	}
}