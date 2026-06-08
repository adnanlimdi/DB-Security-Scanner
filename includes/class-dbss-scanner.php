<?php
/**
 * Database scanner.
 *
 * @package DB_Security_Scanner
 * @since   1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class DBSS_Scanner
 *
 * Scans WordPress database tables for malware patterns.
 *
 * @since 1.0.0
 */
class DBSS_Scanner {

	/**
	 * Run a full database scan.
	 *
	 * @since  1.0.0
	 * @return array<int,array<string,string>> List of threat records found.
	 */
	public function scan() {
		global $wpdb;

		$threats  = array();
		$patterns = DBSS_Patterns::get_all();
		$targets  = DBSS_Patterns::get_scan_targets();
		$seen     = array();

		foreach ( $targets as $table => $columns ) {
			$pk = DBSS_Patterns::get_primary_key( $table );

			foreach ( $columns as $column ) {
				foreach ( $patterns as $pattern => $label ) {

					// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$rows = $wpdb->get_results(
						$wpdb->prepare(
							"SELECT {$pk} AS row_id, LEFT({$column}, 300) AS snippet
							 FROM {$table}
							 WHERE {$column} LIKE %s
							 LIMIT 50",
							'%' . $wpdb->esc_like( $pattern ) . '%'
						),
						ARRAY_A
					);
					// phpcs:enable

					if ( empty( $rows ) ) {
						continue;
					}

					foreach ( $rows as $row ) {
						// Deduplicate: one entry per table + row_id combination.
						$dedup_key = $table . '|' . $row['row_id'];
						if ( isset( $seen[ $dedup_key ] ) ) {
							continue;
						}
						$seen[ $dedup_key ] = true;

						$threats[] = array(
							'table'   => $table,
							'column'  => $column,
							'pk'      => $pk,
							'row_id'  => $row['row_id'],
							'pattern' => $pattern,
							'label'   => $label,
							'snippet' => wp_strip_all_tags( $row['snippet'] ),
						);
					}
				}
			}
		}

		return $threats;
	}
}
