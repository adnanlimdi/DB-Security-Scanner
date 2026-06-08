<?php
/**
 * Database cleaner.
 *
 * @package DB_Security_Scanner
 * @since   1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class DBSS_Cleaner
 *
 * Removes malicious code from a given database row.
 *
 * @since 1.0.0
 */
class DBSS_Cleaner {

	/**
	 * Clean a single database row.
	 *
	 * Strips <script> blocks and known malware patterns from the specified
	 * column value and saves the sanitised value back to the database.
	 *
	 * @since  1.0.0
	 * @param  string $table  Table name.
	 * @param  string $column Column name.
	 * @param  string $pk     Primary key column name.
	 * @param  int    $row_id Primary key value.
	 * @return bool           True on success, false on failure or no change.
	 */
	
	public function clean_row( $table, $column, $pk, $row_id ) {
		global $wpdb;

		switch ( $table ) {

			case $GLOBALS['wpdb']->posts:
			$columns = array( 'post_title', 'post_content', 'post_excerpt' );
			break;

			case $GLOBALS['wpdb']->options:
			$columns = array( 'option_value' );
			break;

			case $GLOBALS['wpdb']->postmeta:
			$columns = array( 'meta_value' );
			break;

			case $GLOBALS['wpdb']->usermeta:
			$columns = array( 'meta_value' );
			break;

			case $GLOBALS['wpdb']->comments:
			$columns = array( 'comment_content', 'comment_author_url' );
			break;

			default:
			return false;
		}

	
			 /* Validate column strictly */
		if ( ! in_array( $column, $columns, true ) ) {
			return false;
		}

		// Primary key is fixed for WP core tables
		$cache_key = "db_scanner_{$table}_{$row_id}";
		$row       = wp_cache_get( $cache_key, 'db_security_scanner' );

		$pk     = 'ID';

		if ( false === $row ) {

			$row = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT $column FROM $table WHERE $pk = %d",
					$row_id
				),
				ARRAY_A
			);

			wp_cache_set( $cache_key, $row, 'db_security_scanner', HOUR_IN_SECONDS );
		}

		if ( empty( $row ) ) {
			return false;
		}

		$original = $row[ $column ];
		$cleaned  = $this->remove_malicious_code( $original );

		if ( $cleaned === $original ) {
			return false;
		}

		// UPDATE must also be safe (IMPORTANT FIX)
		$result = $wpdb->update(
			$table,
			array(
				$column => $cleaned,
			),
			array(
				$pk => $row_id,
			),
			array( '%s' ),
			array( '%d' )
		);

		if ( false !== $result ) {
			wp_cache_set(
				$cache_key,
				array(
					$column => $cleaned,
				),
				'db_security_scanner',
				HOUR_IN_SECONDS
			);
		}

		return false !== $result;
}

	/**
	 * Clean all rows returned by a scan.
	 *
	 * @since  1.0.0
	 * @param  array $threats Array of threat records from DBSS_Scanner::scan().
	 * @return array{cleaned: int, failed: int}
	 */
	public function clean_all( $threats ) {
		$cleaned = 0;
		$failed  = 0;

		foreach ( $threats as $threat ) {
			$success = $this->clean_row(
				$threat['table'],
				$threat['column'],
				$threat['pk'],
				(int) $threat['row_id']
			);

			if ( $success ) {
				$cleaned++;
			} else {
				$failed++;
			}
		}

		return array(
			'cleaned' => $cleaned,
			'failed'  => $failed,
		);
	}

	/**
	 * Remove malicious code from a string.
	 *
	 * @since  1.0.0
	 * @param  string $content Raw content from the database.
	 * @return string          Sanitised content.
	 */
	private function remove_malicious_code( $content ) {

		// Remove complete <script>...</script> blocks (case-insensitive, multiline).
		$content = preg_replace( '/<script\b[^>]*>.*?<\/script>/is', '', $content );

		// Remove partial injections that start mid-content without an opening tag.
		$content = preg_replace( '/&&document\.getElementById.*?<\/script>/is', '', $content );

		// Remove self-executing function patterns.
		$content = preg_replace( '/\(function\s*\(\s*\)\s*\{.*?<\/script>/is', '', $content );

		// Strip any remaining closing </script> orphans left by partial removals.
		$content = preg_replace( '/<\/script>/i', '', $content );

		return $content;
	}
}
