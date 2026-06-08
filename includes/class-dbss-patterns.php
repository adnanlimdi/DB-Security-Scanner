<?php
/**
 * Malware patterns library.
 *
 * @package DB_Security_Scanner
 * @since   1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class DBSS_Patterns
 *
 * Holds all known malware pattern definitions.
 *
 * @since 1.0.0
 */
class DBSS_Patterns {

	/**
	 * Returns an associative array of malware patterns.
	 *
	 * Key   = string to search for in the database.
	 * Value = human-readable label shown in the UI.
	 *
	 * @since  1.0.0
	 * @return array<string,string>
	 */
	public static function get_all() {
		return array(
			'searchranktraffic'              => __( 'Traffic hijacking script (searchranktraffic.live)', 'db-security-scanner' ),
			'wordpressnull'                  => __( 'Nulled plugin backdoor (wordpressnull.org)', 'db-security-scanner' ),
			'base64_decode'                  => __( 'Base64 decode payload', 'db-security-scanner' ),
			'eval(gzinflate'                 => __( 'Obfuscated gzinflate eval payload', 'db-security-scanner' ),
			'eval(base64'                    => __( 'Base64 eval injection', 'db-security-scanner' ),
			"document.createElement('script')" => __( 'Dynamic script element injection', 'db-security-scanner' ),
			'systemLoad('                    => __( 'Known malware loader function', 'db-security-scanner' ),
			'http2_session_id'               => __( 'Tracking cookie injection', 'db-security-scanner' ),
			'fromCharCode'                   => __( 'Character code obfuscation', 'db-security-scanner' ),
			'shell_exec('                    => __( 'Shell execution attempt', 'db-security-scanner' ),
			'passthru('                      => __( 'Shell passthru attempt', 'db-security-scanner' ),
			'FilesMan'                       => __( 'Web shell signature (FilesMan)', 'db-security-scanner' ),
			'c99shell'                       => __( 'C99 web shell', 'db-security-scanner' ),
			'r57shell'                       => __( 'R57 web shell', 'db-security-scanner' ),
			'aHR0cHM6Ly'                     => __( 'Base64-encoded URL payload', 'db-security-scanner' ),
		);
	}

	/**
	 * Returns the list of tables and their columns to scan.
	 *
	 * @since  1.0.0
	 * @return array<string,array<string>>
	 */
	public static function get_scan_targets() {
		global $wpdb;

		return array(
			$wpdb->posts    => array( 'post_content', 'post_excerpt', 'post_title' ),
			$wpdb->options  => array( 'option_value' ),
			$wpdb->postmeta => array( 'meta_value' ),
			$wpdb->usermeta => array( 'meta_value' ),
			$wpdb->comments => array( 'comment_content', 'comment_author_url' ),
		);
	}

	/**
	 * Returns the primary key column name for a given table.
	 *
	 * @since  1.0.0
	 * @param  string $table Table name.
	 * @return string
	 */
	public static function get_primary_key( $table ) {
		global $wpdb;

		$map = array(
			$wpdb->posts    => 'ID',
			$wpdb->options  => 'option_id',
			$wpdb->postmeta => 'meta_id',
			$wpdb->usermeta => 'umeta_id',
			$wpdb->comments => 'comment_ID',
		);

		return isset( $map[ $table ] ) ? $map[ $table ] : 'ID';
	}
}
