<?php
/**
 * @package     Azure Joomla Authentication
 * @subpackage  System.azure
 * @version 	0.0.1
 *
 * @copyright   Copyright (C) 2005 - 2016 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;
jimport('joomla.log.log');
/**
 * Azure Authentication Plugin
 *
 * @since  0.1
 */

class PlgSystemAzure extends JPlugin
{
	/**
	 * Application object.
	 *
	 * @var    JApplicationCms
	 * @since  1.0
	 */
	protected $app;
	private $session=null;
	/**
	 * Azure Authentication run on onAfterInitialise
	 * Only purpose is to check if we come from azure and if we have code and call login function
	 *
	 * @return  void
	 *
	 * @since   0.1
	 * @throws  InvalidArgumentException
	 */
	public function onAfterInitialise()
	{
		// Get the application if not done by JPlugin. This may happen during upgrades from Joomla 2.5.
		$app = JFactory::getApplication();

		// No remember me for admin.
		//if ($this->app->isAdmin())	{	return;	}

		
		
		
		// Check for a cookie if user is not logged in
		if (JFactory::getUser()->guest)
		{
			$code=$app->input->get('code','');
			$state=$app->input->get('session_state','');
			
			if (strlen($code) && strlen($state)) 
			{
				$app->login(array("username"=>"", "password"=>"none"));
				
				$session=$this->getSession();
				$return = $session->get("azure_return","");
					
				$session->set("azure_return","");
				if (strlen($return))
					$app->redirect($return);
				else
					$app->redirect(JUri::base(false));
				return;
				
			}
		}
	}
	/**
	 * Get current session (Joomla 2.5 and 3.x are different)
	 *
	 * @return  JSession object
	 *
	 * @since   0.1
	 */
	private function getSession()
	{
		if ($this->session==null)
		{
			if(version_compare(JVERSION,'3.0.0','<')){
				// Joomla 2.5
				$this->session=JFactory::getSession();
			}
			else {
				// Joomla > 2.5
				$this->session=JFactory::getApplication()->getSession();
			}
		}
		return $this->session;
	}
	
}
