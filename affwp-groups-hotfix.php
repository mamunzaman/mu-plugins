<?php
/**
 * Plugin Name: AffWP Groups Hotfix (disable duplicate bootstrap)
 */

add_action('plugins_loaded', function () {
    // AffiliateWP’s groups manager is hooked via this function name in the stack trace.
    // Remove it before it runs to avoid double registration fatals.
    remove_action('plugins_loaded', 'affwp_affiliate_groups_manager', 10);

    // Safety: also stop any late attempts to register again.
    add_filter('affwp_groups_allow_register_connectable', '__return_false', 9999);
}, 0);