<?php
/**
 * Plugin Name: Admin Notice Filter (Core only)
 * Description: Hide all admin notices except WordPress core/system notices.
 */

// Remove all notices early
add_action( 'admin_head', function() {
    // Remove plugin/theme notices
    remove_all_actions( 'admin_notices' );
    remove_all_actions( 'all_admin_notices' );
    remove_all_actions( 'network_admin_notices' );

    // Re-add core update nag
    add_action( 'admin_notices', 'update_nag', 3 );
    
    // Re-add site health nags (WordPress 5.2+)
    if ( function_exists( 'wp_site_health_scheduled_check' ) ) {
        add_action( 'admin_notices', 'wp_site_health_admin_notices' );
    }
}, 1 );