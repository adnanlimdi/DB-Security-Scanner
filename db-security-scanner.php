<?php
/**
 * Plugin Name:       DB Security Scanner
 * Plugin URI:        https://wordpress.org/plugins/db-security-scanner/
 * Description:       Scans and removes malicious scripts and malware injections from your WordPress database tables.
 * Version:           1.0.0
 * Requires at least: 5.0
 * Requires PHP:      7.4
 * Author:            Adnan limdiwala
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       db-security-scanner
 * Domain Path:       /languages
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Define plugin constants.
define( 'DBSS_VERSION',     '1.0.0' );
define( 'DBSS_PLUGIN_DIR',  plugin_dir_path( __FILE__ ) );
define( 'DBSS_PLUGIN_URL',  plugins_url( '/', __FILE__ ) );
define( 'DBSS_PLUGIN_FILE', __FILE__ );

// Load includes.
require_once DBSS_PLUGIN_DIR . 'includes/class-dbss-patterns.php';
require_once DBSS_PLUGIN_DIR . 'includes/class-dbss-scanner.php';
require_once DBSS_PLUGIN_DIR . 'includes/class-dbss-cleaner.php';
require_once DBSS_PLUGIN_DIR . 'includes/class-dbss-admin.php';

/**
 * Initialise the plugin.
 *
 * @since 1.0.0
 */
function dbss_init() {
	$admin = new DBSS_Admin();
	$admin->init();
}
add_action( 'plugins_loaded', 'dbss_init' );
