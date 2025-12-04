<?php

/**
 * Plugin Name: Micropayment for Guest Checkout
 * Description: Zeigt Micropayment CreditCard Web (und Sofort) auch für nicht eingeloggte Benutzer im Checkout an.
 */

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Fügt Micropayment-Gateways für Gäste wieder zu den verfügbaren Zahlarten hinzu.
 */
add_filter('woocommerce_available_payment_gateways', function ($gateways) {

    // Im Admin oder wenn User eingeloggt ist, nichts verändern
    if (is_admin() || is_user_logged_in()) {
        return $gateways;
    }

    // Stelle sicher, dass WooCommerce initialisiert ist
    if (! function_exists('WC')) {
        return $gateways;
    }

    // Alle registrierten Gateways holen
    $all_gateways = WC()->payment_gateways()->payment_gateways();

    // IDs der Micropayment-Gateways, die wir für Gäste erlauben wollen
    $mipa_ids = array(
        'mipa_ccard_web', // Micropayment CreditCard Web
        'mipa_sofort',    // Micropayment Sofort (falls du den auch willst)
    );

    foreach ($mipa_ids as $id) {
        // Wenn dieses Gateway noch nicht als "available" drin ist, aber global existiert -> hinzufügen
        if (! isset($gateways[$id]) && isset($all_gateways[$id])) {
            $gateways[$id] = $all_gateways[$id];
        }
    }

    return $gateways;
}, 20);
