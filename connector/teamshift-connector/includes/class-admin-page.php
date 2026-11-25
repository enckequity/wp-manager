<?php
/**
 * Tools → TeamShift Connector admin page.
 *
 * @package TeamShiftConnector
 */

namespace TeamShiftConnector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Admin page: requirements, one-time connection string, settings, log.
 */
class Admin_Page {

	const SLUG           = 'teamshift-connector';
	const CAPABILITY     = 'manage_options';
	const NONCE_ACTION   = 'wmhc_create_connection';
	const SETTINGS_GROUP = 'wmhc_settings_group';

	/**
	 * Shared service.
	 *
	 * @var Service
	 */
	private $service;

	/**
	 * Page hook suffix.
	 *
	 * @var string
	 */
	private $hook = '';

	/**
	 * Result of a connection creation in this request (never persisted).
	 *
	 * @var array<string, string>|\WP_Error|null
	 */
	private $created = null;

	/**
	 * Constructor.
	 *
	 * @param Service $service Service.
	 */
	public function __construct( Service $service ) {
		$this->service = $service;
	}

	/**
	 * Adds the Tools submenu page.
	 *
	 * @return void
	 */
	public function register_menu() {
		$hook = add_management_page(
			__( 'TeamShift Connector', 'teamshift-connector' ),
			__( 'TeamShift Connector', 'teamshift-connector' ),
			self::CAPABILITY,
			self::SLUG,
			array( $this, 'render' )
		);
		if ( $hook ) {
			$this->hook = $hook;
			add_action( 'load-' . $hook, array( $this, 'handle_post' ) );
		}
	}

	/**
	 * Registers the settings option.
	 *
	 * @return void
	 */
	public function register_settings() {
		register_setting(
			self::SETTINGS_GROUP,
			Settings::OPTION,
			array(
				'type'              => 'object',
				'sanitize_callback' => array( Settings::class, 'sanitize' ),
				'default'           => Settings::defaults(),
				'show_in_rest'      => false,
			)
		);
		add_action( 'update_option_' . Settings::OPTION, array( $this, 'log_settings_change' ), 10, 2 );
		add_action( 'add_option_' . Settings::OPTION, array( $this, 'log_settings_added' ), 10, 2 );
	}

	/**
	 * Logs settings changes.
	 *
	 * @param mixed $old_value Old value.
	 * @param mixed $value     New value.
	 * @return void
	 */
	public function log_settings_change( $old_value, $value ) {
		unset( $old_value );
		$this->log_settings( $value );
	}

	/**
	 * Logs the first settings save.
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  Value.
	 * @return void
	 */
	public function log_settings_added( $option, $value ) {
		unset( $option );
		$this->log_settings( $value );
	}

	/**
	 * Writes a settings.save log entry.
	 *
	 * @param mixed $value Settings.
	 * @return void
	 */
	private function log_settings( $value ) {
		$items = array();
		foreach ( Settings::sanitize( $value ) as $key => $enabled ) {
			$items[] = $key . '=' . ( $enabled ? 'on' : 'off' );
		}
		$this->service->log()->add( 'settings.save', $items, 'success', array( 'source' => 'admin' ) );
	}

	/**
	 * Adds a "Settings" link on the Plugins screen.
	 *
	 * @param string[] $links Links.
	 * @return string[]
	 */
	public function action_links( $links ) {
		$url = admin_url( 'tools.php?page=' . self::SLUG );
		array_unshift( $links, '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Connect TeamShift', 'teamshift-connector' ) . '</a>' );
		return $links;
	}

	/**
	 * Enqueues the page script on our page only.
	 *
	 * @param string $hook_suffix Current admin page.
	 * @return void
	 */
	public function enqueue_assets( $hook_suffix ) {
		if ( $hook_suffix !== $this->hook ) {
			return;
		}
		wp_enqueue_script( 'wmhc-admin', WMHC_URL . 'assets/admin.js', array(), WMHC_VERSION, true );
		wp_localize_script(
			'wmhc-admin',
			'wmhcAdmin',
			array(
				'statusUrl' => rest_url( WMHC_REST_NAMESPACE . '/status' ),
				'nonce'     => wp_create_nonce( 'wp_rest' ),
				'i18n'      => array(
					'copied'      => __( 'Copied', 'teamshift-connector' ),
					'copyFailed'  => __( 'Copy failed. Select the text and copy it manually.', 'teamshift-connector' ),
					'checking'    => __( 'Checking…', 'teamshift-connector' ),
					'reachable'   => __( 'Reachable. Connector REST routes respond.', 'teamshift-connector' ),
					'unreachable' => __( 'Not reachable from your browser. A security plugin or server rule may block the REST API.', 'teamshift-connector' ),
				),
			)
		);
	}

	/**
	 * Handles the "Create connection for TeamShift" form before output starts.
	 *
	 * @return void
	 */
	public function handle_post() {
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
			return;
		}
		if ( ! isset( $_POST['wmhc_action'] ) || 'create_connection' !== sanitize_key( wp_unslash( $_POST['wmhc_action'] ) ) ) {
			return;
		}
		check_admin_referer( self::NONCE_ACTION );

		$user = wp_get_current_user();
		if ( ! current_user_can( self::CAPABILITY ) || ! current_user_can( 'create_app_password', $user->ID ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to create a connection.', 'teamshift-connector' ), 403 );
		}

		$this->created = $this->service->create_connection( $user );

		// The page shows a secret: never let it be cached.
		nocache_headers();
	}

	/**
	 * Renders the page.
	 *
	 * @return void
	 */
	public function render() {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to access this page.', 'teamshift-connector' ) );
		}

		$user         = wp_get_current_user();
		$requirements = $this->service->requirements();
		$connections  = $this->service->list_connections( $user->ID );
		$settings     = $this->service->settings()->all();
		$log          = $this->service->get_log( 20 );
		$profile_url  = admin_url( 'profile.php#application-passwords-section' );
		?>
		<div class="wrap" id="wmhc-page">
			<h1><?php esc_html_e( 'TeamShift Connector', 'teamshift-connector' ); ?></h1>
			<p><?php esc_html_e( 'Connect this site to your TeamShift assistant so it can check for and run updates. TeamShift signs in with an Application Password, never your login password.', 'teamshift-connector' ); ?></p>

			<?php $this->render_created_notice( $profile_url ); ?>

			<h2><?php esc_html_e( 'Connection status', 'teamshift-connector' ); ?></h2>
			<table class="widefat striped" style="max-width:900px">
				<tbody>
				<?php foreach ( $requirements as $key => $requirement ) : ?>
					<tr>
						<th scope="row" style="width:220px"><?php echo esc_html( $requirement['label'] ); ?></th>
						<td style="width:80px">
							<?php if ( $requirement['ok'] ) : ?>
								<span class="dashicons dashicons-yes-alt" aria-hidden="true"></span> <?php esc_html_e( 'OK', 'teamshift-connector' ); ?>
							<?php else : ?>
								<span class="dashicons dashicons-warning" aria-hidden="true"></span> <?php esc_html_e( 'Problem', 'teamshift-connector' ); ?>
							<?php endif; ?>
						</td>
						<td>
							<?php echo esc_html( $requirement['detail'] ); ?>
							<?php if ( 'rest_api' === $key ) : ?>
								<br /><span id="wmhc-rest-check"></span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>

			<h2><?php esc_html_e( 'Connect TeamShift', 'teamshift-connector' ); ?></h2>
			<p>
				<?php
				printf(
					/* translators: %s: user login */
					esc_html__( 'This creates an Application Password named "TeamShift Connector" for your account (%s) and shows a one-time connection string to paste into TeamShift.', 'teamshift-connector' ),
					'<strong>' . esc_html( $user->user_login ) . '</strong>'
				);
				?>
			</p>
			<form method="post" action="<?php echo esc_url( admin_url( 'tools.php?page=' . self::SLUG ) ); ?>">
				<?php wp_nonce_field( self::NONCE_ACTION ); ?>
				<input type="hidden" name="wmhc_action" value="create_connection" />
				<?php submit_button( __( 'Create connection for TeamShift', 'teamshift-connector' ), 'primary', 'wmhc_create', false, $requirements['application_passwords']['ok'] ? array() : array( 'disabled' => 'disabled' ) ); ?>
			</form>

			<?php if ( $connections ) : ?>
				<h3><?php esc_html_e( 'Existing TeamShift connections for your account', 'teamshift-connector' ); ?></h3>
				<table class="widefat striped" style="max-width:900px">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Name', 'teamshift-connector' ); ?></th>
							<th><?php esc_html_e( 'Created', 'teamshift-connector' ); ?></th>
							<th><?php esc_html_e( 'Last used', 'teamshift-connector' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $connections as $connection ) : ?>
						<tr>
							<td><?php echo esc_html( $connection['name'] ); ?></td>
							<td><?php echo esc_html( $this->format_time( $connection['created'] ) ); ?></td>
							<td><?php echo esc_html( $connection['last_used'] ? $this->format_time( $connection['last_used'] ) : __( 'Never', 'teamshift-connector' ) ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<p><a href="<?php echo esc_url( $profile_url ); ?>"><?php esc_html_e( 'Revoke connections under Users → Profile → Application Passwords', 'teamshift-connector' ); ?></a></p>
			<?php endif; ?>

			<h2><?php esc_html_e( 'What TeamShift may update', 'teamshift-connector' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'options.php' ) ); ?>">
				<?php settings_fields( self::SETTINGS_GROUP ); ?>
				<fieldset>
					<label>
						<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[allow_core_updates]" value="1" <?php checked( $settings['allow_core_updates'] ); ?> />
						<?php esc_html_e( 'Allow WordPress core updates (minor releases, for example 6.8.1 → 6.8.2)', 'teamshift-connector' ); ?>
					</label>
					<br />
					<label>
						<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[allow_major_core_updates]" value="1" <?php checked( $settings['allow_major_core_updates'] ); ?> />
						<?php esc_html_e( 'Allow major WordPress core updates (for example 6.8 → 6.9)', 'teamshift-connector' ); ?>
					</label>
				</fieldset>
				<p class="description"><?php esc_html_e( 'Plugin, theme and translation updates are always allowed for users with the matching capability. TeamShift does not take backups: make sure your host does.', 'teamshift-connector' ); ?></p>
				<?php submit_button( __( 'Save settings', 'teamshift-connector' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Recent actions', 'teamshift-connector' ); ?></h2>
			<?php if ( empty( $log['entries'] ) ) : ?>
				<p><?php esc_html_e( 'No actions yet.', 'teamshift-connector' ); ?></p>
			<?php else : ?>
				<table class="widefat striped" style="max-width:1100px">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Time', 'teamshift-connector' ); ?></th>
							<th><?php esc_html_e( 'User', 'teamshift-connector' ); ?></th>
							<th><?php esc_html_e( 'Action', 'teamshift-connector' ); ?></th>
							<th><?php esc_html_e( 'Items', 'teamshift-connector' ); ?></th>
							<th><?php esc_html_e( 'Result', 'teamshift-connector' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $log['entries'] as $entry ) : ?>
						<tr>
							<td><?php echo esc_html( isset( $entry['timestamp'] ) ? $this->format_time( (int) $entry['timestamp'] ) : '' ); ?></td>
							<td><?php echo esc_html( isset( $entry['user_login'] ) ? $entry['user_login'] : '' ); ?></td>
							<td><code><?php echo esc_html( isset( $entry['action'] ) ? $entry['action'] : '' ); ?></code><?php echo isset( $entry['type'] ) ? ' ' . esc_html( (string) $entry['type'] ) : ''; ?></td>
							<td><?php echo esc_html( isset( $entry['items'] ) ? implode( ', ', (array) $entry['items'] ) : '' ); ?></td>
							<td><?php echo esc_html( isset( $entry['result'] ) ? $entry['result'] : '' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Shows the one-time connection string (or the error).
	 *
	 * @param string $profile_url Profile URL.
	 * @return void
	 */
	private function render_created_notice( $profile_url ) {
		if ( null === $this->created ) {
			return;
		}
		if ( is_wp_error( $this->created ) ) {
			printf( '<div class="notice notice-error"><p>%s</p></div>', esc_html( $this->created->get_error_message() ) );
			return;
		}
		?>
		<div class="notice notice-success" id="wmhc-connection">
			<p><strong><?php esc_html_e( 'Connection created. Copy this connection string into TeamShift now.', 'teamshift-connector' ); ?></strong></p>
			<p>
				<textarea id="wmhc-connection-string" class="large-text code" rows="3" readonly="readonly"><?php echo esc_textarea( $this->created['connection_string'] ); ?></textarea>
			</p>
			<p>
				<button type="button" class="button button-secondary" id="wmhc-copy" data-target="wmhc-connection-string"><?php esc_html_e( 'Copy', 'teamshift-connector' ); ?></button>
				<span id="wmhc-copy-status" aria-live="polite"></span>
			</p>
			<p>
				<?php
				printf(
					/* translators: 1: application password name, 2: link to the profile page */
					esc_html__( 'It is shown only once and contains a password. It was saved as the Application Password "%1$s"; you can revoke it any time under %2$s.', 'teamshift-connector' ),
					esc_html( $this->created['name'] ),
					'<a href="' . esc_url( $profile_url ) . '">' . esc_html__( 'Users → Profile → Application Passwords', 'teamshift-connector' ) . '</a>'
				);
				?>
			</p>
			<p><?php esc_html_e( 'Save it in TeamShift as a workspace secret rather than pasting it into a chat.', 'teamshift-connector' ); ?></p>
		</div>
		<?php
	}

	/**
	 * Formats a timestamp in the site timezone.
	 *
	 * @param int $timestamp Unix timestamp.
	 * @return string
	 */
	private function format_time( $timestamp ) {
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $timestamp );
	}
}
