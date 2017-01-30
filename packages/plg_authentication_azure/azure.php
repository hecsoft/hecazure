<?php
/**
 * @package     Azure Joomla Authentication
 * @subpackage  Authentication.azure
 *
 * @copyright   Copyright (C) 2005 - 2014 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 *
 * @doc 		https://docs.microsoft.com/fr-fr/azure/active-directory/develop/active-directory-protocols-oauth-code
 */

defined('_JEXEC') or die;
jimport('joomla.log.log');

/**
 * Azure Authentication Plugin
 *
 * @package     Azure Joomla Authentication
 * @subpackage  Authentication.azure
 * @since       2.5
 */
class PlgAuthenticationAzure extends JPlugin
{
	
	private  $logger=null;
	private $session=null;
	
		
	/**
	 * This method should handle any authentication and report back to the subject
	 *
	 * @param   array   $credentials  Array holding the user credentials
	 * @param   array   $options      Array of extra options
	 * @param   object  &$response    Authentication response object
	 *
	 * @return  boolean
	 *
	 * @since   2.5
	 */
	public function onUserAuthenticate($credentials, $options, &$response)
	{
		// Load plugin language
		$this->loadLanguage();
		
		// Init local Vars
		$gotoAuth=false;
		$success=false;
		$promptConsent=false;
				
		// Get the application if not done by JPlugin. This may happen during upgrades from Joomla 2.5.
		$this->app = JFactory::getApplication();
		$session=$this->getSession();
		
		$code=$this->app->input->get('code','');
		$state=$this->app->input->get('session_state','');
		
		//Get parameters
		$idApp = $this->params->get('ApplicationID', '');
		$idAppUri=$this->params->get('ApplicationIDUri', '');
		$appSecret = $this->params->get('ApplicationSecret', '');
		$idRep = $this->params->get('DirectoryID', '');
		$idAppUri=$this->params->get('ApplicationIDUri', '');
		$domain = $this->params->get('domain', '');
		$usergroup = $this->params->get('group', array(),'array');
		$createuser = $this->params->get('createuser', '0')=='1';
		$verifySsl =  $this->params->get('sslverifypeer', '1')!='0';
		$debug =  $this->params->get('debug', '0')=='1';
		
		// Backend authentication allowed?
		if (JFactory::getApplication()->isAdmin() && !$this->params->get('backendLogin', 0)){	return;	}
		// Azure parameters OK?
		if (!strlen($idApp) || !strlen($idAppUri) || !function_exists('curl_init')) 
		{
			if ($debug)
			{
				if(!function_exists('curl_init')) $this->addLog(JText::_("PLG_AZURE_ERROR_USER_NOCURL"),JLog::ERROR);	
			}
			if (!strlen($idApp) || !strlen($idAppUri)) { $this->addLog(JText::_("PLG_AZURE_ERROR_USER_BADCONFIG"),JLog::ERROR);	}
			return;
		}
		
		// Return from Azure Login Page?
		if (strlen($code) && strlen($state)) {
			if ($debug) { $this->addLog("Return from Azure Login page code=".$code,JLog::DEBUG);	}
			$success = 0;
			
			//$session=$this->app->getSession();
			$current = $session->get("azure_redirect_uri",'' );
			$return = $session->get("azure_return",'' );
			$tokenUrl="https://login.windows.net/$idRep/oauth2/token";
	

			$params=array('redirect_uri'=>$current,'grant_type'=>'authorization_code'
					,'resource'=>$idApp //$idAppUri
					,'client_id'=>$idApp,'code'=>$code, 
					'client_secret'=>$appSecret);

			//open connection
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			/*On indique à curl de ne pas retourner les headers http de la réponse dans la chaine de retour*/
			curl_setopt($ch, CURLOPT_HEADER, false);
			//set the url, number of POST vars, POST data
			curl_setopt($ch,CURLOPT_URL, $tokenUrl);

			/*On indique à curl d'envoyer une requete post*/
			curl_setopt($ch, CURLOPT_POST,true);
			/*On donne les paramêtre de la requete post*/
			curl_setopt($ch, CURLOPT_POSTFIELDS,$params);

			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verifySsl);
			//curl_setopt($ch, CURLOPT_CAINFO, dirname(__FILE__) . DIRECTORY_SEPARATOR . 'cacert.pem');
			//curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
			
			if ($debug) { $this->addLog("Ask Token",JLog::DEBUG);	}

			//execute post
			$result = curl_exec($ch);
			//close connection
			
			
			if($result === false)
			{
				$this->addLog("Azure Plugin : Token curl error :".curl_error($ch),JLog::ERROR);	
				$response->status        = JAuthentication::STATUS_FAILURE;
				$response->error_message = curl_error($ch);
				curl_close($ch);
				return;
			}
			curl_close($ch);
			$result=json_decode($result);
			if (isset($result->access_token))
			{
				if ($debug) { $this->addLog("Azure Plugin : Token OK",JLog::DEBUG);	}
				$this->app->input->set('code','');
				$this->app->input->set('session_state','');
				$success=true;
				$idToken=$result->id_token;
				$tokenPart=explode('.', $idToken);
				$header = json_decode(base64_decode($tokenPart[0]));
				$infos = json_decode(base64_decode($tokenPart[1]));
				
				$username=$infos->upn;
				$email=$infos->upn;
				$azureUser= $this->isAzureUser($username);
				if (!$azureUser["domainOk"])
				{
					if ($debug) { $this->addLog("Azure Plugin : Not belong to domains",JLog::DEBUG);	}
					$response->status        = JAuthentication::STATUS_DENIED;
					$response->error_message = JText::_("PLG_AZURE_ERROR_BAD_DOMAIN");
					return;
				}
				if (!$createuser)
				{
					if ($azureUser["user"]==null)
					{
						$this->addLog("Azure Plugin : User doesn't exist",JLog::WARNING);
						$response->status        = JAuthentication::STATUS_DENIED;
						$response->error_message = JText::_("PLG_AZURE_ERROR_USER_NOTEXISTS");
						return;
					}
				}
				
				$response->status        = JAuthentication::STATUS_SUCCESS;
				$response->email         = $email;
				$response->type          = 'Azure';
				$response->password_clear = "";
				// Reset the username to what we ended up using
				$response->username = $username;
				$response->fullname = $infos->name;   //$infos->given_name.' '.$infos->family_name;
				$credentials['username']=$username;
				$credentials['password']=sha1($infos->oid.$infos->iat);
				$options['return']=$return;
				$session->set("azure_redirect_uri", '');
				$session->set("azure_last_username", $username);
				$session->set("azure_entry_url", '');
				$session->set("azure_return", '');
				return;
			}
			else 
			{
				if ($debug) { $this->addLog("Azure Plugin : Token Error for ".$username." : ".$result->error_description,JLog::WARNING);	}
				$success=false;
				$gotoAuth=true;
				$promptConsent=true;
			}
			
		}
		else $gotoAuth=true;
		
		// Redirect to Azure Login page
		if ($gotoAuth) 
		{
			
			$username=$credentials['username'];
			if ($username=='') $username=$session->get('azure_last_username','');
			$azureUser= $this->isAzureUser($username);
			if (!$azureUser["status"]) // User can't use Azure Account
			{
				if ($debug) { $this->addLog("Azure Plugin : User ".$username." doesn't use Azure account)-".$azureUser["message"],JLog::DEBUG);	}
				$response->status        = JAuthentication::STATUS_FAILURE;
				$response->error_message = $azureUser["message"];
				return;
				
			}
			else 
				$username = $azureUser["username"];
			// Define default index page as redirect, a system plugin will handle the code reception and call again this plugin
			$current=JUri::base(false);
			
			// If token failed try again with consent prompt (azure ask to user permission)
			if ($promptConsent) {	$prompt="&prompt=consent";	} else $prompt = "";
			if ($debug) { $this->addLog("Azure Plugin : Redirect to Office (".$username.") ".$prompt,JLog::DEBUG);	}
			$authUrl= $redirectUrl="https://login.windows.net/$idRep/oauth2/authorize?client_id=$idApp&response_type=code&response_mode=query$prompt&redirect_uri=".$current."&ressource=".$idAppUri."&login_hint=".$username;
			
			$session->set("azure_redirect_uri", $current);
			$session->set("azure_last_username", $username);
			$session->set("azure_entry_url", $options['entry_url']);
			if (isset($options['return']))
				$session->set("azure_return", $options['return']);
			else
				$session->set("azure_return", '');
			$this->app->redirect($authUrl);
		}
	
		if ($debug) { $this->addLog("Azure Plugin (".$username.") : Default",JLog::DEBUG);	}
		$response->type = 'Azure';
		$response->status        = JAuthentication::STATUS_FAILURE;
		$response->error_message = JText::sprintf('JGLOBAL_AUTH_FAILED', $message);
		
		
	}
	function onUserAfterLogin($options)
	{
		if ($options['responseType']=='Azure')
		{
			$app = JFactory::getApplication();
			$session=$this->getSession();
			$return = $session->get("azure_return","");
			
			$session->set("azure_return","");
			if (strlen($return))
				$app->redirect($return);
			else 
				$app->redirect(JUri::base(false));
		}
	}
	
	private function getUser($name) 
	{
		$db=JFactory::getDbo();
		$query=$db->getQuery(true);
		$query->select('id')->from("#__users")->where ("username=".$db->quote($name));
		$db->setQuery($query);
		$user=$db->loadObject();
		if ($user)
			return JFactory::getUser($user->id);
		else 
			return false;
	}

	private function isAzureUser($username)
	{
		$domain = $this->params->get('domain', '');
		
		$usergroup = $this->params->get('group', array(),'array');
		$usergroup = array_map(function($v) { return intval($v);} , $usergroup);
		$domains = explode(";", $domain);
		$status=true;
		$domainOk=true;
		$groupOk=true;
		$user=false;
		$message=array();
		$user = $this->getUser($username);	// Get Joomla user from his username
		// Usergroup selected
		if (count($usergroup)>0)
		{
			
		
			if (!$user)	// User doesn't exist and need group --> Fail
			{
				$status=false;
				$message[]=JText::_("PLG_AZURE_ERROR_USER_NOTEXISTS");
			}
			
			else
			{
				$authGroups=$user->getAuthorisedGroups();
				$diff= array_intersect($usergroup,$authGroups );
				if (count ($diff)==0)  // User don't belong to selected group --> Fail
			
				{
					$status=false;
					$groupOk=false;
					$message[]=JText::_("PLG_AZURE_ERROR_USER_NOTINGROUP");
				}
			}
		}
			
		// Check if username is in the defined domaine
		
		if (count($domains)) 
		{
			$domainOk=false;
			foreach($domains as $domain)
			{
				if (stripos($username, '@'.$domain))
				{
					$domainOk=true;
					break;
				}
			}
			if (!$domainOk)
			{
				$status=false;
				$message[]= JText::sprintf("PLG_AZURE_ERROR_BAD_DOMAIN", $domain);
				$domainOk=false;
			}
		}
		return array("status"=>$status, "message"=> implode(",", $message),"user"=>$user ,"username"=>$username, "domainOk"=>$domainOk, "groupOk"=>$groupOk);
	}
	
	private function addLog($comment, $status)
	{
		if ($this->logger == null)
		{
			$config = array(
					'text_file' => 'logging.log'
			);
			if(version_compare(JVERSION,'3.0.0','<')){
				// Joomla 2.5
				jimport('joomla.log.loggers.formattedtext');
				$logger = new JLoggerFormattedText($config);
				
			}
			else 
			{
				// Joomla 3
				jimport('joomla.log.logger.formattedtext');
				$logger = new JLogLoggerFormattedtext($config);
			}
			$this->logger=$logger;
		}			
		// Comment is a string
		// $status can be JLog::INFO, JLog::WARNING, JLog::ERROR, JLog::ALL, JLog::EMERGENCY or JLog::CRITICAL
		$entry = new JLogEntry($comment, $status);
		$this->logger->addEntry($entry);
	}
	
	private function getSession()
	{
		if ($this->session==null)
		{
			if(version_compare(JVERSION,'3.0.0','<')){
				$this->session=JFactory::getSession();
			}
			else {
				$this->session=$this->app->getSession();
			}
		}
		return $this->session;
	}
	
}
