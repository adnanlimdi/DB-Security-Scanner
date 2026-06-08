<?php
/**
 * Admin interface.
 *
 * @package DB_Security_Scanner
 * @since   1.0.0
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class DBSS_Admin
 *
 * Registers the admin menu page and handles all AJAX requests.
 *
 * @since 1.0.0
 */
class DBSS_Admin {

	/**
	 * Attach all WordPress hooks.
	 *
	 * @since 1.0.0
	 */
	public function init() {
		add_action( 'admin_menu',              array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts',   array( $this, 'enqueue_assets' ) );
		add_action( 'wp_ajax_dbss_scan',       array( $this, 'ajax_scan' ) );
		add_action( 'wp_ajax_dbss_clean_row',  array( $this, 'ajax_clean_row' ) );
		add_action( 'wp_ajax_dbss_clean_all',  array( $this, 'ajax_clean_all' ) );
		add_action( 'wp_ajax_dbss_db_download', array( $this, 'ajax_db_download' ) );
	}

	/**
	 * Register the admin menu item.
	 *
	 * @since 1.0.0
	 */
	public function register_menu() {
		add_menu_page(
			__( 'DB Security Scanner', 'db-security-scanner' ),
			__( 'DB Security Scanner', 'db-security-scanner' ),
			'manage_options',
			'db-security-scanner',
			array( $this, 'render_page' ),
			'dashicons-shield-alt',
			99
		);
	}

	/**
	 * Enqueue admin styles and scripts.
	 *
	 * @since 1.0.0
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue_assets( $hook ) {
		if ( 'toplevel_page_db-security-scanner' !== $hook ) {
			return;
		}

		wp_enqueue_style(
			'dbss-admin',
			DBSS_PLUGIN_URL . 'assets/admin.css',
			array(),
			DBSS_VERSION
		);

		wp_enqueue_script(
			'dbss-admin',
			DBSS_PLUGIN_URL . 'assets/admin.js',
			array( 'jquery' ),
			DBSS_VERSION,
			true
		);

		wp_localize_script(
			'dbss-admin',
			'dbssData',
			array(
				'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
				'nonce'    => wp_create_nonce( 'dbss_nonce' ),
				'dbName'   => DB_NAME,
				'i18n'     => array(
					'scanning'        => __( 'Scanning database tables for malicious patterns…', 'db-security-scanner' ),
					'scanComplete'    => __( 'Scan complete.', 'db-security-scanner' ),
					'noThreats'       => __( 'No threats found. Your database looks clean!', 'db-security-scanner' ),
					'threatsFound'    => __( 'threat(s) found. Review below and clean.', 'db-security-scanner' ),
					'cleaning'        => __( 'Cleaning all threats…', 'db-security-scanner' ),
					'cleanDone'       => __( 'Cleaned', 'db-security-scanner' ),
					'cleanFailed'     => __( 'failed', 'db-security-scanner' ),
					'confirmClean'    => __( 'This will attempt to clean ALL threats. Make sure you have a database backup. Continue?', 'db-security-scanner' ),
					'ready'           => __( 'Ready to scan. Click "Scan Database" to begin.', 'db-security-scanner' ),
					'rowCleaned'      => __( 'Cleaned row', 'db-security-scanner' ),
					'rowFailed'       => __( 'Failed to clean row', 'db-security-scanner' ),
					'done'            => __( '✓ Done', 'db-security-scanner' ),
					'clean'           => __( 'Clean', 'db-security-scanner' ),
					'dbDownloading'   => __( 'Generating backup… please wait.', 'db-security-scanner' ),
					'dbDone'          => __( 'Backup ready — download started.', 'db-security-scanner' ),
					'dbError'         => __( 'Backup failed. Check server permissions.', 'db-security-scanner' ),
					'confirmDownload' => __( 'This will generate a full SQL backup of your database. Continue?', 'db-security-scanner' ),
				),
			)
		);
	}

	/**
	 * AJAX handler — scan the database.
	 *
	 * @since 1.0.0
	 */
	public function ajax_scan() {
		check_ajax_referer( 'dbss_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'db-security-scanner' ) ), 403 );
		}

		$scanner = new DBSS_Scanner();
		$results = $scanner->scan();

		wp_send_json_success(
			array(
				'results' => $results,
				'count'   => count( $results ),
			)
		);
	}

	/**
	 * AJAX handler — clean a single database row.
	 *
	 * @since 1.0.0
	 */
	public function ajax_clean_row() {
		check_ajax_referer( 'dbss_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'db-security-scanner' ) ), 403 );
		}

		$table  = isset( $_POST['table'] )  ? sanitize_text_field( wp_unslash( $_POST['table'] ) )  : '';
		$column = isset( $_POST['column'] ) ? sanitize_text_field( wp_unslash( $_POST['column'] ) ) : '';
		$pk     = isset( $_POST['pk'] )     ? sanitize_text_field( wp_unslash( $_POST['pk'] ) )     : '';
		$row_id = isset( $_POST['row_id'] ) ? absint( $_POST['row_id'] )                            : 0;

		if ( ! $table || ! $column || ! $pk || ! $row_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid parameters.', 'db-security-scanner' ) ) );
		}

		$allowed_tables = array_keys( DBSS_Patterns::get_scan_targets() );
		if ( ! in_array( $table, $allowed_tables, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Table not allowed.', 'db-security-scanner' ) ) );
		}

		$cleaner = new DBSS_Cleaner();
		$success = $cleaner->clean_row( $table, $column, $pk, $row_id );

		wp_send_json_success( array( 'cleaned' => $success ) );
	}

	/**
	 * AJAX handler — clean all threats found by a fresh scan.
	 *
	 * @since 1.0.0
	 */
	public function ajax_clean_all() {
		check_ajax_referer( 'dbss_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'db-security-scanner' ) ), 403 );
		}

		$scanner = new DBSS_Scanner();
		$threats = $scanner->scan();

		$cleaner = new DBSS_Cleaner();
		$result  = $cleaner->clean_all( $threats );

		wp_send_json_success( $result );
	}

	/**
	 * AJAX handler — generate and stream a SQL database backup.
	 *
	 * Uses WordPress's $wpdb to export all tables as SQL INSERT statements.
	 * Streams the file directly as a download to avoid memory issues.
	 *
	 * @since 1.0.0
	 */
	public function ajax_db_download() {
		check_ajax_referer( 'dbss_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized.', 'db-security-scanner' ), 403 );
		}

		global $wpdb;

		$tables_only = isset( $_POST['tables'] ) ? sanitize_text_field( wp_unslash( $_POST['tables'] ) ) : 'all';
		$filename    = 'db-backup-' . gmdate( 'Y-m-d-His' ) . '.sql';

		// Set headers for file download.
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		// Disable WP output buffering.
		if ( ob_get_level() ) {
			ob_end_clean();
		}

		// Determine which tables to export.
		if ( 'security' === $tables_only ) {
			$tables = array_keys( DBSS_Patterns::get_scan_targets() );
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$all    = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );
			$tables = array_column( $all, 0 );
		}

		// SQL header.
		echo "-- DB Security Scanner Backup\n";
		echo '-- Generated: ' . gmdate( 'Y-m-d H:i:s' ) . " UTC\n";
		echo '-- Database: ' . DB_NAME . "\n";
		echo "-- -----------------------------------------------\n\n";
		echo "SET FOREIGN_KEY_CHECKS=0;\n";
		echo "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n\n";

		foreach ( $tables as $table ) {
			$table = esc_sql( $table );

			echo "\n-- Table: `{$table}`\n";
			echo "DROP TABLE IF EXISTS `{$table}`;\n";

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$create = $wpdb->get_row( "SHOW CREATE TABLE `{$table}`", ARRAY_N );
			if ( $create ) {
				echo $create[1] . ";\n\n"; // phpcs:ignore WordPress.Security.EscapeOutput
			}

			// Export rows in chunks to avoid memory limits.
			$offset     = 0;
			$chunk_size = 500;

			do {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$rows = $wpdb->get_results(
					$wpdb->prepare( "SELECT * FROM `{$table}` LIMIT %d OFFSET %d", $chunk_size, $offset ),
					ARRAY_A
				);

				if ( empty( $rows ) ) {
					break;
				}

				$columns = '`' . implode( '`, `', array_keys( $rows[0] ) ) . '`';

				foreach ( $rows as $row ) {
					$values = array();
					foreach ( $row as $value ) {
						if ( null === $value ) {
							$values[] = 'NULL';
						} else {
							$values[] = "'" . esc_sql( $value ) . "'";
						}
					}
					echo 'INSERT INTO `' . $table . '` (' . $columns . ') VALUES (' . implode( ', ', $values ) . ");\n"; // phpcs:ignore WordPress.Security.EscapeOutput
				}

				$offset += $chunk_size;

			} while ( count( $rows ) === $chunk_size );

			echo "\n";
		}

		echo "SET FOREIGN_KEY_CHECKS=1;\n";
		echo "-- End of backup\n";

		exit;
	}

	/**
	 * Render the admin page HTML.
	 *
	 * @since 1.0.0
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
		<div class="wrap dbss-wrap">

			<h1>
				<span class="dashicons dashicons-shield-alt" style="font-size:26px;width:26px;height:26px;vertical-align:middle;margin-right:6px;color:#2271b1;"></span>
				<?php esc_html_e( 'DB Security Scanner', 'db-security-scanner' ); ?>
			</h1>
			<span class="dbss-subtitle dbss-notice-info"><?php esc_html_e( 'Scans: wp_posts · wp_options · wp_postmeta · wp_usermeta · wp_comments', 'db-security-scanner' ); ?></span>

			<div class="dbss-notice-warning">
				<span class="dashicons dashicons-warning"></span>
				<?php esc_html_e( 'Always take a full database backup before running Clean All. Use the Download Backup button below or your hosting panel first.', 'db-security-scanner' ); ?>
			</div>

			<!-- Scanner actions -->
			<div class="dbss-actions">
				<button id="dbss-btn-scan" class="button button-primary">
					<span class="dashicons dashicons-search"></span>
					<?php esc_html_e( 'Scan Database', 'db-security-scanner' ); ?>
				</button>
				<button id="dbss-btn-clean-all" class="button dbss-btn-danger" disabled>
					<span class="dashicons dashicons-trash"></span>
					<?php esc_html_e( 'Clean All Threats', 'db-security-scanner' ); ?>
				</button>
				<button id="dbss-btn-export" class="button dbss-btn-success" style="display:none">
					<span class="dashicons dashicons-media-spreadsheet"></span>
					<?php esc_html_e( 'Export CSV Report', 'db-security-scanner' ); ?>
				</button>
			</div>

			<!-- Status bar -->
			<div id="dbss-status" class="dbss-status">
				<?php esc_html_e( 'Ready to scan. Click "Scan Database" to begin.', 'db-security-scanner' ); ?>
			</div>

			<!-- Stats -->
			<div class="dbss-stats-grid">
				<div class="dbss-stat-card">
					<span id="dbss-stat-scanned" class="dbss-stat-number dbss-stat-blue">&mdash;</span>
					<span class="dbss-stat-label"><?php esc_html_e( 'Tables Scanned', 'db-security-scanner' ); ?></span>
				</div>
				<div class="dbss-stat-card">
					<span id="dbss-stat-threats" class="dbss-stat-number dbss-stat-red">&mdash;</span>
					<span class="dbss-stat-label"><?php esc_html_e( 'Threats Found', 'db-security-scanner' ); ?></span>
				</div>
				<div class="dbss-stat-card">
					<span id="dbss-stat-cleaned" class="dbss-stat-number dbss-stat-green">&mdash;</span>
					<span class="dbss-stat-label"><?php esc_html_e( 'Threats Cleaned', 'db-security-scanner' ); ?></span>
				</div>
			</div>

			<!-- Results table -->
			<div id="dbss-results-wrap"></div>

			<hr class="dbss-divider">

			<!-- Database download section -->
			<div class="dbss-db-section" style="display:none">
				<h3>
					<span class="dashicons dashicons-database"></span>
					<?php esc_html_e( 'Download Database Backup', 'db-security-scanner' ); ?>
				</h3>
				<p><?php esc_html_e( 'Generate and download an SQL backup of your WordPress database. Always backup before cleaning.', 'db-security-scanner' ); ?></p>

				<div class="dbss-db-form">
					<label for="dbss-db-scope" class="screen-reader-text"><?php esc_html_e( 'Tables to export', 'db-security-scanner' ); ?></label>
					<select id="dbss-db-scope">
						<option value="all"><?php esc_html_e( 'All Tables (Full Backup)', 'db-security-scanner' ); ?></option>
						<option value="security"><?php esc_html_e( 'Scanned Tables Only', 'db-security-scanner' ); ?></option>
					</select>

					<button id="dbss-btn-db-download" class="button dbss-btn-db">
						<span class="dashicons dashicons-database-export"></span>
						<?php esc_html_e( 'Download Backup (.sql)', 'db-security-scanner' ); ?>
					</button>
				</div>

				<div id="dbss-db-progress" class="dbss-db-progress">
					<span class="dashicons dashicons-update dbss-spinner"></span>
					<span id="dbss-db-progress-text"></span>
				</div>
			</div>

		</div>
		<?php
	}
}
