<?php
/**
 * Fix WWPP fatal in admin Products list by removing its grouped price hook.
 */
add_action( 'current_screen', function ( $screen ) {
    if ( empty( $screen->id ) || $screen->id !== 'edit-product' ) {
        return;
    }

    // Remove WWPP's filter that crashes on grouped price html.
    // We don't know the exact instance, so scan callbacks and remove the one from the class.
    $tag = 'woocommerce_grouped_price_html';
    global $wp_filter;

    if ( isset( $wp_filter[ $tag ] ) && is_object( $wp_filter[ $tag ] ) ) {
        $wpf = $wp_filter[ $tag ];
        // WP 5.0+ uses WP_Hook with ->callbacks.
        if ( isset( $wpf->callbacks ) && is_array( $wpf->callbacks ) ) {
            foreach ( $wpf->callbacks as $priority => $callbacks ) {
                foreach ( $callbacks as $id => $cb ) {
                    $fn = $cb['function'];
                    if ( is_array( $fn ) && is_object( $fn[0] ) ) {
                        $class = get_class( $fn[0] );
                        if ( strpos( $class, 'WWP_Wholesale_Price_Grouped_Product' ) !== false ) {
                            remove_filter( $tag, $fn, $priority );
                        }
                    }
                }
            }
        }
    }

    // Also short-circuit wholesale price calculations in admin (extra safety).
    add_filter( 'wwp_filter_wholesale_price_shop', function ( $price ) {
        return $price;
    }, 1, 5 );
} );