<?php
/**
 * Plugin Name: AffWP Hotfix — stop duplicate connectables
 */

add_action('plugins_loaded', function () {
    // Stop both managers from auto-bootstrapping if they exist.
    remove_action('plugins_loaded', 'affwp_affiliate_groups_manager', 10);
    remove_action('plugins_loaded', 'affwp_creative_category_manager', 10);

    // If AffiliateWP uses filters to allow registering connectables, veto them.
    add_filter('affwp_groups_allow_register_connectable', '__return_false', 9999);
    add_filter('affwp_creative_categories_allow_register_connectable', '__return_false', 9999);
}, 0);