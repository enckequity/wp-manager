<?php
/**
 * Plugin Name:       TeamShift Connector
 * Plugin URI:        https://teamshift.io
 * Description:       Lets your TeamShift assistant check and run plugin, theme, core and translation updates on this site through an authenticated REST API (Application Passwords) and the Abilities API.
 * Version:           0.1.0
 * Requires at least: 6.5
 * Requires PHP:      7.4
 * Author:            TeamShift
 * Author URI:        https://teamshift.io
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       teamshift-connector
 *
 * @package TeamShiftConnector
 */

/*
TeamShift Connector
Copyright (C) 2026 danieljwonder (original Website Manager connector)
Modifications Copyright (C) 2026 TeamShift

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WMHC_VERSION', '0.1.0' );
define( 'WMHC_FILE', __FILE__ );
define( 'WMHC_DIR', plugin_dir_path( __FILE__ ) );
define( 'WMHC_URL', plugin_dir_url( __FILE__ ) );
define( 'WMHC_REST_NAMESPACE', 'teamshift-connector/v1' );

require_once WMHC_DIR . 'includes/class-settings.php';
require_once WMHC_DIR . 'includes/class-action-log.php';
require_once WMHC_DIR . 'includes/class-service.php';
require_once WMHC_DIR . 'includes/class-rest-controller.php';
require_once WMHC_DIR . 'includes/class-abilities.php';
require_once WMHC_DIR . 'includes/class-admin-page.php';
require_once WMHC_DIR . 'includes/class-plugin.php';

\TeamShiftConnector\Plugin::instance()->init();
