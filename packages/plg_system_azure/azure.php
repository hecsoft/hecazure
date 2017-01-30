<?php
/**
 * @package     Azure Joomla Authentication
 * @subpackage  System.azure
 * @version 	1.0.0
 *
 * @copyright   Copyright (C) 2005 - 2016 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;
jimport('joomla.log.log');
/**
 * Azure Authentication Plugin
 *
 * @since  1.0
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

	/**
	 * Azure Authentication run on onAfterInitialise
	 * Only purpose is to check if we come from azure and if we have code
	 *
	 * @return  void
	 *
	 * @since   1.0
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
				return;
				
			}
		}
	}

	
}
