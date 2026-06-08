/**
 * DB Security Scanner — Admin JavaScript
 *
 * @package DB_Security_Scanner
 * @since   1.0.0
 */

/* global dbssData */
( function ( $ ) {
	'use strict';

	var scanResults  = [];
	var cleanedCount = 0;

	var $status      = $( '#dbss-status' );
	var $btnScan     = $( '#dbss-btn-scan' );
	var $btnClean    = $( '#dbss-btn-clean-all' );
	var $btnExport   = $( '#dbss-btn-export' );
	var $btnDbDl     = $( '#dbss-btn-db-download' );
	var $dbProgress  = $( '#dbss-db-progress' );
	var $dbProgText  = $( '#dbss-db-progress-text' );
	var $wrap        = $( '#dbss-results-wrap' );

	// ── Helpers ──────────────────────────────────────────────

	/**
	 * Update the status bar.
	 *
	 * @param {string} message  Status message.
	 * @param {string} modifier CSS modifier class.
	 */
	function setStatus( message, modifier ) {
		$status
			.removeClass( 'is-scanning is-found is-clean is-cleaning' )
			.addClass( modifier || '' )
			.text( message );
	}

	/**
	 * Update a stat card value.
	 *
	 * @param {string} id  Element ID (without #).
	 * @param {mixed}  val Display value.
	 */
	function setStat( id, val ) {
		$( '#' + id ).text( val );
	}

	/**
	 * Escape HTML special characters.
	 *
	 * @param  {string} str Raw string.
	 * @return {string}     Escaped string.
	 */
	function escHtml( str ) {
		return String( str )
			.replace( /&/g,  '&amp;'  )
			.replace( /</g,  '&lt;'   )
			.replace( />/g,  '&gt;'   )
			.replace( /"/g,  '&quot;' )
			.replace( /'/g,  '&#039;' );
	}

	/**
	 * Send an AJAX POST request.
	 *
	 * @param {string}   action WordPress AJAX action.
	 * @param {Object}   data   Extra POST fields.
	 * @param {Function} cb     Called with response.data on success.
	 */
	function doAjax( action, data, cb ) {
		$.post(
			dbssData.ajaxUrl,
			$.extend( { action: action, nonce: dbssData.nonce }, data ),
			function ( response ) {
				if ( response.success ) {
					cb( response.data );
				} else {
					var msg = ( response.data && response.data.message ) ? response.data.message : 'Request failed.';
					setStatus( msg, '' );
				}
			}
		).fail( function ( xhr ) {
			setStatus( 'Request error: ' + xhr.statusText, '' );
		} );
	}

	// ── Render results table ─────────────────────────────────

	/**
	 * Render the threat results table.
	 *
	 * @param {Array} results Array of threat objects from the server.
	 */
	function renderResults( results ) {
		if ( ! results.length ) {
			$wrap.html(
				'<div class="dbss-empty">' +
					'<span class="dashicons dashicons-yes-alt"></span>' +
					'<p>' + escHtml( dbssData.i18n.noThreats ) + '</p>' +
					'<small>scan complete — no malicious patterns detected</small>' +
				'</div>'
			);
			return;
		}

		var html = '<table class="dbss-results widefat">';
		html    += '<colgroup>';
		html    += '<col style="width:42px"><col style="width:170px"><col style="width:130px">';
		html    += '<col style="width:80px"><col style="width:210px"><col><col style="width:90px">';
		html    += '</colgroup>';
		html    += '<thead><tr>';
		html    += '<th>#</th><th>Table</th><th>Column</th>';
		html    += '<th>Row ID</th><th>Threat</th><th>Snippet</th><th>Action</th>';
		html    += '</tr></thead><tbody>';

		$.each( results, function ( i, r ) {
			html += '<tr id="dbss-row-' + i + '" data-index="' + i + '">';
			html += '<td style="color:#646970">' + ( i + 1 ) + '</td>';
			html += '<td><span class="dbss-badge dbss-badge-table">' + escHtml( r.table ) + '</span></td>';
			html += '<td><code style="font-size:12px">' + escHtml( r.column ) + '</code></td>';
			html += '<td><strong>' + escHtml( String( r.row_id ) ) + '</strong></td>';
			html += '<td><span class="dbss-badge dbss-badge-threat">' + escHtml( r.label ) + '</span></td>';
			html += '<td><span class="dbss-snippet" title="' + escHtml( r.snippet ) + '">' + escHtml( r.snippet ) + '</span></td>';
			html += '<td><button class="button button-small dbss-clean-row-btn" data-index="' + i + '">' + escHtml( dbssData.i18n.clean ) + '</button></td>';
			html += '</tr>';
		} );

		html += '</tbody></table>';
		$wrap.html( html );
	}

	// ── Scan button ──────────────────────────────────────────

	$btnScan.on( 'click', function () {
		$btnScan
			.prop( 'disabled', true )
			.find( '.dashicons' )
			.removeClass( 'dashicons-search' )
			.addClass( 'dbss-spinner dashicons-update' );

		setStatus( dbssData.i18n.scanning, 'is-scanning' );
		setStat( 'dbss-stat-scanned', '5' );
		setStat( 'dbss-stat-threats', '…' );
		setStat( 'dbss-stat-cleaned', cleanedCount || '0' );
		$wrap.html( '' );

		doAjax( 'dbss_scan', {}, function ( data ) {
			$btnScan
				.prop( 'disabled', false )
				.find( '.dashicons' )
				.removeClass( 'dbss-spinner dashicons-update' )
				.addClass( 'dashicons-search' );

			scanResults = data.results;
			var count   = data.count;

			setStat( 'dbss-stat-threats', count );

			if ( 0 === count ) {
				setStatus( '✓ ' + dbssData.i18n.noThreats, 'is-clean' );
				$btnClean.prop( 'disabled', true );
				$btnExport.hide();
			} else {
				setStatus( '⚠ ' + count + ' ' + dbssData.i18n.threatsFound, 'is-found' );
				$btnClean.prop( 'disabled', false );
				$btnExport.show();
			}

			renderResults( scanResults );
		} );
	} );

	// ── Per-row clean button (event delegation) ──────────────

	$wrap.on( 'click', '.dbss-clean-row-btn', function () {
		var $btn  = $( this );
		var index = parseInt( $btn.data( 'index' ), 10 );
		var r     = scanResults[ index ];

		if ( ! r ) {
			return;
		}

		$btn.prop( 'disabled', true ).text( '…' );

		doAjax(
			'dbss_clean_row',
			{ table: r.table, column: r.column, pk: r.pk, row_id: r.row_id },
			function ( data ) {
				if ( data.cleaned ) {
					$( '#dbss-row-' + index ).addClass( 'dbss-row-cleaned' );
					$btn.text( dbssData.i18n.done ).addClass( 'is-done' );
					cleanedCount++;
					setStat( 'dbss-stat-cleaned', cleanedCount );
					setStatus( dbssData.i18n.rowCleaned + ' #' + r.row_id + ' in ' + r.table, 'is-clean' );
				} else {
					$btn.prop( 'disabled', false ).text( dbssData.i18n.clean );
					setStatus( dbssData.i18n.rowFailed + ' #' + r.row_id + '. Try manual edit.', '' );
				}
			}
		);
	} );

	// ── Clean All button ─────────────────────────────────────

	$btnClean.on( 'click', function () {
		if ( ! window.confirm( dbssData.i18n.confirmClean ) ) {
			return;
		}

		$btnClean
			.prop( 'disabled', true )
			.find( '.dashicons' )
			.addClass( 'dbss-spinner' );

		setStatus( dbssData.i18n.cleaning, 'is-cleaning' );

		doAjax( 'dbss_clean_all', {}, function ( data ) {
			$btnClean.find( '.dashicons' ).removeClass( 'dbss-spinner' );
			cleanedCount = data.cleaned;
			setStat( 'dbss-stat-cleaned', cleanedCount );
			setStatus(
				dbssData.i18n.cleanDone + ' ' + data.cleaned +
				' · ' + dbssData.i18n.cleanFailed + ': ' + data.failed +
				'. Re-scanning…',
				'is-clean'
			);
			// Auto re-scan after clean to verify.
			setTimeout( function () {
				$btnScan.trigger( 'click' );
			}, 1500 );
		} );
	} );

	// ── Export CSV button ────────────────────────────────────

	$btnExport.on( 'click', function () {
		if ( ! scanResults.length ) {
			return;
		}

		var csv  = 'Table,Column,Row ID,Threat,Snippet\n';
		var date = new Date().toISOString().slice( 0, 10 );

		$.each( scanResults, function ( i, r ) {
			csv += '"' + r.table   + '",' +
			       '"' + r.column  + '",' +
			       '"' + r.row_id  + '",' +
			       '"' + r.label   + '",' +
			       '"' + r.snippet.replace( /"/g, "'" ) + '"\n';
		} );

		var blob = new Blob( [ csv ], { type: 'text/csv;charset=utf-8;' } );
		var url  = URL.createObjectURL( blob );
		var a    = document.createElement( 'a' );

		a.href     = url;
		a.download = 'db-security-scan-' + date + '.csv';
		document.body.appendChild( a );
		a.click();
		document.body.removeChild( a );
		URL.revokeObjectURL( url );
	} );

	// ── Database Download button ─────────────────────────────

	$btnDbDl.on( 'click', function () {
		if ( ! window.confirm( dbssData.i18n.confirmDownload ) ) {
			return;
		}

		var scope = $( '#dbss-db-scope' ).val();

		$btnDbDl.prop( 'disabled', true ).find( '.dashicons' ).addClass( 'dbss-spinner' );
		$dbProgress.addClass( 'is-visible' );
		$dbProgText.text( dbssData.i18n.dbDownloading );

		// Build a hidden form to POST and trigger file download.
		// Using a form submit avoids AJAX binary-response issues.
		var $form = $( '<form>', {
			method : 'POST',
			action : dbssData.ajaxUrl,
			target : '_blank'
		} ).append(
			$( '<input>', { type: 'hidden', name: 'action', value: 'dbss_db_download' } ),
			$( '<input>', { type: 'hidden', name: 'nonce',  value: dbssData.nonce      } ),
			$( '<input>', { type: 'hidden', name: 'tables', value: scope               } )
		);

		$( 'body' ).append( $form );
		$form.submit();
		$form.remove();

		// Re-enable button after a short delay.
		setTimeout( function () {
			$btnDbDl.prop( 'disabled', false ).find( '.dashicons' ).removeClass( 'dbss-spinner' );
			$dbProgText.text( dbssData.i18n.dbDone );
			setTimeout( function () {
				$dbProgress.removeClass( 'is-visible' );
			}, 3000 );
		}, 2500 );
	} );

} )( jQuery );
