<?php
/**
 * Plugin Name: ICT — Astra Checkout Customer Info 2-Step Login + Wordfence 2FA (MU)
 * Description: Replaces Astra “Customer information” section on checkout with a custom 2-step login flow including Wordfence 2FA support.
 * Author: ICT / Mamun
 * Version: 2.1.0
 * Must Use: true
 */

namespace ICT\AstCheckoutTwoStep2FA;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Check if user has Wordfence Login Security 2FA active.
 *
 * This mirrors the logic used by Wordfence when showing
 * "Wordfence 2FA is active" in the user profile screen.
 *
 * @param int $user_id
 * @return bool
 */
function ict_user_has_wordfence_2fa( $user_id ) {
	$has_2fa = false;

	// 1) Use Wordfence's official controller if available.
	if ( class_exists( '\WordfenceLS\Controller_Users' ) ) {
		try {
			$controller = \WordfenceLS\Controller_Users::shared();

			if ( $controller && method_exists( $controller, 'has_2fa_active' ) ) {
				$wp_user = get_user_by( 'id', $user_id );
				if ( $wp_user instanceof \WP_User ) {
					$has_2fa = (bool) $controller->has_2fa_active( $wp_user );
				}
			}
		} catch ( \Throwable $e ) {
			error_log( 'ICT 2FA: Error calling Controller_Users::has_2fa_active for user ' . $user_id . ' – ' . $e->getMessage() );
		}
	}

	// 2) Fallback: check Wordfence 2FA secrets table directly.
	if ( ! $has_2fa ) {
		global $wpdb;
		$table = $wpdb->prefix . 'wfls_2fa_secrets';

		// Ensure table exists.
		$exists = $wpdb->get_var(
			$wpdb->prepare( "SHOW TABLES LIKE %s", $table )
		);

		if ( $exists === $table ) {
			$row = $wpdb->get_var(
				$wpdb->prepare(
					"SELECT user_id FROM {$table} WHERE user_id = %d LIMIT 1",
					$user_id
				)
			);
			if ( ! empty( $row ) ) {
				$has_2fa = true;
			}
		}
	}

	return (bool) $has_2fa;
}

/**
 * AJAX: Check if user exists and if they have Wordfence 2FA.
 * Called when user leaves the username/email field.
 */
add_action( 'wp_ajax_nopriv_ict_ast_check_user', __NAMESPACE__ . '\\ajax_check_user' );
function ajax_check_user() {
    try {
		if ( isset( $_POST['nonce'] ) && ! wp_verify_nonce( $_POST['nonce'], 'ict_checkout_nonce' ) ) {
			wp_send_json_error( [ 'msg' => __( 'Security check failed.', 'ict' ) ] );
        }
        
		$username = isset( $_POST['username'] ) ? sanitize_text_field( wp_unslash( $_POST['username'] ) ) : '';
        
		if ( $username === '' ) {
			wp_send_json( [ 'exists' => false, 'msg' => __( 'Please enter username or email.', 'ict' ) ] );
        }

		$user = is_email( $username ) ? get_user_by( 'email', $username ) : get_user_by( 'login', $username );
        
		if ( ! $user ) {
			wp_send_json( [ 'exists' => false ] );
        }

		$has_2fa = ict_user_has_wordfence_2fa( $user->ID );

		wp_send_json(
			[
				'exists'  => true,
				'has_2fa' => $has_2fa,
			]
		);
	} catch ( \Throwable $e ) {
		wp_send_json_error( [ 'msg' => __( 'An error occurred. Please try again.', 'ict' ) ] );
    }
}

/**
 * AJAX: Verify password for existing user and tell JS if 2FA is active.
 * Called when user clicks "Login" in step 1.
 */
add_action( 'wp_ajax_nopriv_ict_ast_verify_password', __NAMESPACE__ . '\\ajax_verify_password' );
function ajax_verify_password() {
    try {
		if ( isset( $_POST['nonce'] ) && ! wp_verify_nonce( $_POST['nonce'], 'ict_checkout_nonce' ) ) {
			wp_send_json_error( [ 'msg' => __( 'Security check failed.', 'ict' ) ] );
        }
        
		$username = isset( $_POST['username'] ) ? sanitize_text_field( wp_unslash( $_POST['username'] ) ) : '';
		$password = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : '';

		if ( $username === '' || $password === '' ) {
			wp_send_json(
				[
					'ok'  => false,
					'msg' => __( 'Please enter username/email and password.', 'ict' ),
				]
			);
        }

		$user = is_email( $username ) ? get_user_by( 'email', $username ) : get_user_by( 'login', $username );
		if ( ! $user ) {
			wp_send_json(
				[
					'ok'  => false,
					'msg' => __( 'User not found.', 'ict' ),
				]
			);
        }

		if ( ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_send_json(
				[
					'ok'  => false,
					'msg' => __( 'Incorrect password.', 'ict' ),
				]
			);
        }

		$has_2fa = ict_user_has_wordfence_2fa( $user->ID );

		wp_send_json(
			[
				'ok'      => true,
				'has_2fa' => $has_2fa,
			]
		);
	} catch ( \Throwable $e ) {
		wp_send_json_error( [ 'msg' => __( 'An error occurred. Please try again.', 'ict' ) ] );
    }
}

/**
 * AJAX: Final login (with or without 2FA token).
 * If 2FA is active, JS sends the 6-digit code as wfls_token.
 * We set $_POST['wfls-token'] so Wordfence Login Security can validate it.
 */
add_action( 'wp_ajax_nopriv_ict_ast_login_with_2fa', __NAMESPACE__ . '\\ajax_login_with_2fa' );
function ajax_login_with_2fa() {
    try {
		if ( isset( $_POST['nonce'] ) && ! wp_verify_nonce( $_POST['nonce'], 'ict_checkout_nonce' ) ) {
			wp_send_json_error( [ 'msg' => __( 'Security check failed.', 'ict' ) ] );
        }
        
		$username = isset( $_POST['username'] ) ? sanitize_text_field( wp_unslash( $_POST['username'] ) ) : '';
		$password = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : '';
		$token    = isset( $_POST['wfls_token'] ) ? sanitize_text_field( wp_unslash( $_POST['wfls_token'] ) ) : '';

		if ( $username === '' || $password === '' ) {
			wp_send_json(
				[
					'ok'  => false,
					'msg' => __( 'Missing credentials.', 'ict' ),
				]
			);
		}

		// Make the token available to Wordfence (they read $_POST['wfls-token']).
		if ( $token !== '' ) {
            $_POST['wfls-token'] = $token;
        }

		$user = wp_signon(
			[
            'user_login'    => $username,
            'user_password' => $password,
            'remember'      => true,
			],
			false
		);

		if ( is_wp_error( $user ) ) {
			wp_send_json(
				[
					'ok'  => false,
					'msg' => $user->get_error_message(),
				]
			);
        }

		wp_send_json( [ 'ok' => true ] );
	} catch ( \Throwable $e ) {
		wp_send_json_error( [ 'msg' => __( 'An error occurred. Please try again.', 'ict' ) ] );
    }
}

/**
 * Make "Create account" checkbox from our custom login UI
 * actually trigger Woo's account creation.
 */
add_filter( 'woocommerce_checkout_fields', __NAMESPACE__ . '\\enable_account_creation', 10, 1 );
function enable_account_creation( $fields ) {
	if ( isset( $_POST['ict_create_account'] ) && $_POST['ict_create_account'] === '1' ) {
        $_POST['createaccount'] = '1';
    }
    return $fields;
}

/**
 * Enqueue inline JS only on checkout for guests.
 * JS replaces Astra's Customer Info login with custom 2-step UI.
 */
add_action(
	'wp_enqueue_scripts',
	function () {
		if ( ! function_exists( 'is_checkout' ) || ! is_checkout() || is_user_logged_in() ) {
        return;
    }

		wp_register_script( 'ict-ast-checkout-2step-2fa', false, [], null, true );
		wp_enqueue_script( 'ict-ast-checkout-2step-2fa' );
    
		wp_localize_script(
			'ict-ast-checkout-2step-2fa',
			'ictCheckoutAjax',
			[
				'ajax_url'        => admin_url( 'admin-ajax.php' ),
				'nonce'           => wp_create_nonce( 'ict_checkout_nonce' ),
				'lost_password_url' => wp_lostpassword_url(),
			]
		);

		wp_add_inline_script(
			'ict-ast-checkout-2step-2fa',
			<<<'JS'
(function(){
	let state = { step: 1, userExists: false, has2FA: false, username: '', password: '' };

	const ajaxCall = (action, data) => {
		const body = new URLSearchParams();
		body.append('action', action);
		if (window.ictCheckoutAjax && window.ictCheckoutAjax.nonce) {
			body.append('nonce', window.ictCheckoutAjax.nonce);
		}
		for (const k in data) body.append(k, data[k]);
		const url = (window.ictCheckoutAjax && window.ictCheckoutAjax.ajax_url) || 
			(window.astra && astra.ajax_url) || 
			(window.ajaxurl) || 
			'/wp-admin/admin-ajax.php';
		return fetch(url, {
			method: 'POST',
			headers: {'Content-Type': 'application/x-www-form-urlencoded'},
			body: body.toString(),
			credentials: 'same-origin'
		}).then(r => {
			if (!r.ok) {
				throw new Error('HTTP error! status: ' + r.status);
			}
			return r.json();
		}).catch(err => {
			console.error('AJAX Error:', err);
			throw err;
		});
	};

	function replaceCustomerInfoWithLoginBox(){
		const wrapper = document.querySelector('#customer_info .woocommerce-billing-fields__customer-info-wrapper');
		if (!wrapper) return false;

		wrapper.innerHTML = '<div id="ict-checkout-login-box" class="ict-checkout-login-box woocommerce-form-login">' +
			'<div class="ast-checkout-form-heading">' +
			'<h3>Customer information</h3>' +
			'<div class="woocommerce-billing-fields__customer-login-label">Already have an account? <a href="javascript:" id="ast-customer-login-url">Log in</a></div>' +
			'</div>' +
			'<p class="form-row form-row-wide" id="ict_username_row">' +
			'<label for="billing_email">Username or email address <span class="required">*</span></label>' +
			'<input type="email" class="input-text" name="billing_email" id="billing_email" placeholder="Username or Email Address" value="" aria-required="true" autocomplete="email username">' +
			'<span class="ict-user-registered-message" id="ict_user_registered_message" style="display:none;">This user is already registered. Please enter the password to continue.</span>' +
			'</p>' +
			'<p class="form-row form-row-wide" id="ict_password_row" style="display:none;">' +
			'<label for="ict_login_password">Password <span class="required">*</span></label>' +
			'<span class="password-input-wrapper">' +
			'<input type="password" class="input-text" id="ict_login_password" autocomplete="current-password">' +
			'<button type="button" class="password-toggle" id="ict_password_toggle" aria-label="Show password"><span class=""></span></button>' +
			'</span>' +
			'</p>' +
			'<p class="form-row form-row-wide" id="ict_create_account_row" style="display:none;">' +
			'<label class="woocommerce-form__label woocommerce-form__label-for-checkbox checkbox">' +
			'<input type="checkbox" class="woocommerce-form__input woocommerce-form__input-checkbox input-checkbox" id="ict_create_account" name="ict_create_account" value="1">' +
			'<span>Create an account?</span>' +
			'</label>' +
			'</p>' +
			'<p class="form-row ict-login-actions">' +
			'<button type="button" class="button ast-customer-login-section__login-button ictmm-aps-btn-secondary" id="ict_login_button">Continue</button>' +
			'<a href="' + (window.ictCheckoutAjax && window.ictCheckoutAjax.lost_password_url ? window.ictCheckoutAjax.lost_password_url : '/my-account/lost-password/') + '" class="ict-lost-password-link" id="ict_lost_password_link" style="display:none;">Lost your password?</a>' +
			'</p>' +
			'<p class="form-row ict-optional-login-message" id="ict_optional_login_message" style="display:none;">Login is optional, you can continue with your order below.</p>' +
			'<div class="ict-login-message"></div>' +
			'</div>';

		const label = document.querySelector('.woocommerce-billing-fields__customer-login-label');
		if (label) label.style.display = 'none';

		const allHeadings = Array.from(document.querySelectorAll('h3')).filter(function(h){
			return h.textContent.trim() === 'Customer information' && !h.closest('#ict-checkout-login-box');
		});
		
		if (allHeadings.length > 0) {
			allHeadings[0].style.display = 'none';
		}

		return true;
	}

	function msgEl(){
		return document.querySelector('#ict-checkout-login-box .ict-login-message');
	}
	function showError(text){
		const box = msgEl();
		if (!box) return;
		box.innerHTML = '<div class="woocommerce-error">' + String(text || 'Error') + '</div>';
	}
	function showInfo(text){
		const box = msgEl();
		if (!box) return;
		box.innerHTML = '<div class="woocommerce-message">' + String(text || '') + '</div>';
	}
	function clearMsg(){
		const box = msgEl();
		if (box) box.innerHTML = '';
	}
	function showElement(el){
		if (!el) return;
		el.style.setProperty('display', 'block', 'important');
		el.style.setProperty('visibility', 'visible', 'important');
	}
	function hideElement(el){
		if (!el) return;
		el.style.setProperty('display', 'none', 'important');
	}
	function slideDown(el){
		if (!el) return;
		el.style.removeProperty('display');
		el.style.removeProperty('visibility');
		el.style.setProperty('max-height', '0', 'important');
		el.style.setProperty('overflow', 'hidden', 'important');
		el.style.setProperty('display', 'block', 'important');
		el.style.setProperty('visibility', 'visible', 'important');
		el.style.setProperty('transition', 'max-height 0.3s ease-out, opacity 0.3s ease-out', 'important');
		el.style.setProperty('opacity', '0', 'important');
		
		setTimeout(function(){
			const height = el.scrollHeight;
			el.style.setProperty('max-height', height + 'px', 'important');
			el.style.setProperty('opacity', '1', 'important');
		}, 10);
		
		setTimeout(function(){
			el.style.removeProperty('max-height');
			el.style.removeProperty('overflow');
			el.style.removeProperty('transition');
			el.style.removeProperty('opacity');
		}, 300);
	}
	function slideUp(el){
		if (!el) return;
		const height = el.scrollHeight;
		el.style.setProperty('max-height', height + 'px', 'important');
		el.style.setProperty('overflow', 'hidden', 'important');
		el.style.setProperty('transition', 'max-height 0.3s ease-in, opacity 0.3s ease-in', 'important');
		el.style.setProperty('opacity', '1', 'important');
		
		setTimeout(function(){
			el.style.setProperty('max-height', '0', 'important');
			el.style.setProperty('opacity', '0', 'important');
		}, 10);
		
		setTimeout(function(){
			el.style.setProperty('display', 'none', 'important');
			el.style.removeProperty('max-height');
			el.style.removeProperty('overflow');
			el.style.removeProperty('transition');
			el.style.removeProperty('opacity');
		}, 300);
	}

	function create2FAInput(){
		console.log('ICT 2FA: create2FAInput called');
		const loginBox = document.getElementById('ict-checkout-login-box');
		if (!loginBox) {
			console.error('ICT 2FA: Login box not found');
			return null;
		}
		
		let tfRow = document.getElementById('ict_2fa_row');
		if (tfRow) {
			console.log('ICT 2FA: 2FA row already exists, showing it');
			showElement(tfRow);
			return tfRow;
		}
		
		let actionsRow = document.querySelector('#ict-checkout-login-box .ict-login-actions');
		console.log('ICT 2FA: Actions row found:', actionsRow);
		if (!actionsRow) {
			const btn = document.getElementById('ict_login_button');
			console.log('ICT 2FA: Button found:', btn);
			if (btn && btn.parentElement) {
				actionsRow = btn.parentElement;
				console.log('ICT 2FA: Using button parent as actions row');
			} else {
				console.error('ICT 2FA: Cannot find actions row or button parent');
				return null;
			}
		}
		
		tfRow = document.createElement('p');
		tfRow.className = 'form-row form-row-wide';
		tfRow.id = 'ict_2fa_row';
		tfRow.style.display = 'block';
		tfRow.style.visibility = 'visible';
		tfRow.innerHTML = '<label for="ict_wfls_token">Two-Factor Code <span class="required">*</span></label>' +
			'<input type="text" class="input-text" id="ict_wfls_token" inputmode="numeric" pattern="[0-9]{6}" placeholder="6-digit code" autocomplete="one-time-code">';
		
		if (actionsRow && actionsRow.parentNode) {
			console.log('ICT 2FA: Inserting 2FA row before actions row');
			actionsRow.parentNode.insertBefore(tfRow, actionsRow);
			showElement(tfRow);
			console.log('ICT 2FA: 2FA row created and inserted:', tfRow);
			return tfRow;
		}
		
		console.error('ICT 2FA: Cannot insert 2FA row - no parent node');
		return null;
	}

	function initLoginLogic(){
		const btn = document.getElementById('ict_login_button');
		const userInp = document.getElementById('billing_email');
		const passInp = document.getElementById('ict_login_password');
		const passRow = document.getElementById('ict_password_row');
		const createRow = document.getElementById('ict_create_account_row');
		const createChk = document.getElementById('ict_create_account');
		const loginLink = document.getElementById('ast-customer-login-url');

		if (!btn || !userInp || !passInp || !passRow || !createRow || !createChk) return;

		if (loginLink) {
			loginLink.addEventListener('click', function(e){
				e.preventDefault();
				const passRowEl = document.getElementById('ict_password_row');
				const lostPwdLink = document.getElementById('ict_lost_password_link');
				const optionalMsg = document.getElementById('ict_optional_login_message');
				if (passRowEl) {
					const computedStyle = window.getComputedStyle(passRowEl);
					const isHidden = computedStyle.display === 'none' || 
					                computedStyle.visibility === 'hidden' ||
					                passRowEl.offsetParent === null;
					
					if (isHidden) {
						slideDown(passRowEl);
						if (btn) btn.textContent = 'Login';
						if (lostPwdLink) showElement(lostPwdLink);
						if (optionalMsg) slideDown(optionalMsg);
						if (passInp) {
							setTimeout(function(){
								passInp.focus();
							}, 350);
						}
					} else {
						slideUp(passRowEl);
						if (btn) btn.textContent = 'Continue';
						if (lostPwdLink) hideElement(lostPwdLink);
						if (optionalMsg) slideUp(optionalMsg);
					}
				}
			});
		}

		const passwordToggle = document.getElementById('ict_password_toggle');
		if (passwordToggle && passInp) {
			passwordToggle.addEventListener('click', function(e){
				e.preventDefault();
				const type = passInp.getAttribute('type') === 'password' ? 'text' : 'password';
				passInp.setAttribute('type', type);
				const icon = passwordToggle.querySelector('.dashicons');
				if (icon) {
					if (type === 'text') {
						icon.classList.remove('dashicons-visibility');
						icon.classList.add('dashicons-hidden');
						passwordToggle.setAttribute('aria-label', 'Hide password');
					} else {
						icon.classList.remove('dashicons-hidden');
						icon.classList.add('dashicons-visibility');
						passwordToggle.setAttribute('aria-label', 'Show password');
					}
				}
			});
		}


		let checkTimeout = null;
		userInp.addEventListener('blur', function(){
			const username = userInp.value.trim();
			if (!username) return;
			
			clearTimeout(checkTimeout);
			checkTimeout = setTimeout(function(){
				clearMsg();
				btn.disabled = true;
				showInfo('Checking...');
				
				ajaxCall('ict_ast_check_user', { username: username }).then(function(res){
					btn.disabled = false;
					if (!res) {
						showError('Network error. Please try again.');
						return;
					}
					
					const usernameRow = document.getElementById('ict_username_row');
					const passRowEl = document.getElementById('ict_password_row');
					const createRowEl = document.getElementById('ict_create_account_row');
					const lostPwdLink = document.getElementById('ict_lost_password_link');
					const optionalMsg = document.getElementById('ict_optional_login_message');
					
					if (res.exists) {
						state.userExists = true;
						state.username = username;
						state.has2FA = (res.has_2fa === true || res.has_2fa === 'true' || res.has_2fa === 1);
						state.step = 1;
						showElement(usernameRow);
						showElement(passRowEl);
						hideElement(createRowEl);
						if (lostPwdLink) showElement(lostPwdLink);
						if (optionalMsg) showElement(optionalMsg);
						const existing2FA = document.getElementById('ict_2fa_row');
						if (existing2FA) hideElement(existing2FA);
						const userMsg = document.getElementById('ict_user_registered_message');
						if (userMsg) showElement(userMsg);
						btn.textContent = 'Login';
						clearMsg();
					} else {
						state.userExists = false;
						state.username = username;
						showElement(usernameRow);
						hideElement(passRowEl);
						showElement(createRowEl);
						if (lostPwdLink) hideElement(lostPwdLink);
						if (optionalMsg) hideElement(optionalMsg);
						const existing2FA = document.getElementById('ict_2fa_row');
						if (existing2FA) hideElement(existing2FA);
						const userMsg = document.getElementById('ict_user_registered_message');
						if (userMsg) hideElement(userMsg);
						btn.textContent = 'Continue';
						clearMsg();
					}
				}).catch(function(){
					btn.disabled = false;
					showError('Network error. Please try again.');
				});
			}, 500);
		});

		createChk.addEventListener('change', function(){
			if (this.checked) {
				const createAccountField = document.querySelector('#createaccount');
				if (createAccountField) {
					createAccountField.checked = true;
				} else {
					const hiddenInput = document.createElement('input');
					hiddenInput.type = 'hidden';
					hiddenInput.name = 'createaccount';
					hiddenInput.value = '1';
					const checkoutForm = document.querySelector('form.checkout');
					if (checkoutForm) checkoutForm.appendChild(hiddenInput);
				}
				const billingFields = document.querySelector('.woocommerce-billing-fields');
				if (billingFields) billingFields.style.display = '';
				btn.style.display = 'none';
			} else {
				const createAccountField = document.querySelector('#createaccount');
				if (createAccountField) createAccountField.checked = false;
				const hiddenInput = document.querySelector('input[name="createaccount"][type="hidden"]');
				if (hiddenInput) hiddenInput.remove();
				btn.style.display = '';
			}
		});

		btn.addEventListener('click', function(){
			const username = userInp.value.trim();
			
			if (state.step === 1) {
				if (!username) {
					showError('Please enter username or email.');
					return;
				}
				
				if (!state.userExists) {
					if (!createChk.checked) {
						showError('Please check "Create an account" to continue.');
						return;
					}
					clearMsg();
					const loginBox = document.getElementById('ict-checkout-login-box');
					if (loginBox) loginBox.style.opacity = '0.6';
					return;
				}
				
				if (state.userExists) {
					const password = passInp.value;
					if (!password) {
						showError('Please enter password.');
						return;
					}
					
					btn.disabled = true;
					showInfo('Verifying password...');
					
					ajaxCall('ict_ast_verify_password', {
						username: username,
						password: password
					}).then(function(res){
						console.log('ICT 2FA: Password verification response:', res);
						btn.disabled = false;
						
						if (!res) {
							console.error('ICT 2FA: No response received');
							showError('No response from server.');
							return;
						}
						
						const responseData = res.data || res;
						console.log('ICT 2FA: Response data:', responseData);
						console.log('ICT 2FA: responseData.ok:', responseData.ok);
						console.log('ICT 2FA: responseData.has_2fa:', responseData.has_2fa);
						
						if (!responseData || responseData.ok !== true) {
							console.log('ICT 2FA: Password verification failed');
							showError(responseData?.msg || res.msg || 'Incorrect password.');
							return;
						}
						
						state.password = password;
						state.has2FA = !!(responseData.has_2fa === true || responseData.has_2fa === 'true' || responseData.has_2fa === 1);
						console.log('ICT 2FA: has2FA set to:', state.has2FA);
						
						const usernameRow = document.getElementById('ict_username_row');
						const passRowEl = document.getElementById('ict_password_row');
						const lostPwdLink = document.getElementById('ict_lost_password_link');
						const optionalMsg = document.getElementById('ict_optional_login_message');
						
						if (state.has2FA) {
							console.log('ICT 2FA: User has 2FA, creating input field');
							state.step = 2;
							
							if (usernameRow) hideElement(usernameRow);
							if (passRowEl) hideElement(passRowEl);
							if (lostPwdLink) hideElement(lostPwdLink);
							if (optionalMsg) hideElement(optionalMsg);
							
							const loginLabel = document.querySelector('#ict-checkout-login-box .woocommerce-billing-fields__customer-login-label');
							if (loginLabel) hideElement(loginLabel);
							
							const tfRowEl = create2FAInput();
							console.log('ICT 2FA: 2FA input created:', tfRowEl);
							if (tfRowEl) {
								const tfInpEl = document.getElementById('ict_wfls_token');
								console.log('ICT 2FA: 2FA input element:', tfInpEl);
								if (tfInpEl) {
									tfInpEl.value = '';
									setTimeout(function(){ 
										tfInpEl.focus();
										tfInpEl.select();
									}, 100);
								}
							btn.textContent = 'Verify & Log in';
								showInfo('Password verified. Please enter your 2FA code.');
							} else {
								console.error('ICT 2FA: Failed to create 2FA input field');
								showError('Failed to create 2FA input field.');
							}
						} else {
							console.log('ICT 2FA: User does not have 2FA');
							state.step = 2;
							const existing2FA = document.getElementById('ict_2fa_row');
							if (existing2FA) hideElement(existing2FA);
							btn.textContent = 'Log in';
							clearMsg();
						}
					}).catch(function(err){
						console.error('ICT 2FA: AJAX error:', err);
						btn.disabled = false;
						showError('Network error. Please try again.');
					});
				}
				return;
			}
			
			if (state.step === 2) {
				if (state.userExists) {
					if (state.has2FA) {
						const usernameRow = document.getElementById('ict_username_row');
						const passRowEl = document.getElementById('ict_password_row');
						const lostPwdLink = document.getElementById('ict_lost_password_link');
						const optionalMsg = document.getElementById('ict_optional_login_message');
						
						hideElement(usernameRow);
						hideElement(passRowEl);
						if (lostPwdLink) hideElement(lostPwdLink);
						if (optionalMsg) hideElement(optionalMsg);
						
						const loginLabel = document.querySelector('#ict-checkout-login-box .woocommerce-billing-fields__customer-login-label');
						if (loginLabel) hideElement(loginLabel);
						
						const tfRowEl = create2FAInput();
						const tfInpEl = document.getElementById('ict_wfls_token');
						
						const code = tfInpEl ? tfInpEl.value.trim() : '';
						if (!/^\d{6}$/.test(code)) {
							showError('Please enter a valid 6-digit code.');
							if (tfInpEl) {
								tfInpEl.focus();
								tfInpEl.select();
							}
							return;
						}
						
						btn.disabled = true;
						showInfo('Verifying 2FA code...');
						
						ajaxCall('ict_ast_login_with_2fa', {
							username: state.username,
							password: state.password,
							wfls_token: code
						}).then(function(res){
							if (res && res.ok) {
								location.reload();
							} else {
								btn.disabled = false;
								showError(res && res.msg ? res.msg : 'Login failed. Please check your code.');
							}
						}).catch(function(){
							btn.disabled = false;
							showError('Network error. Please try again.');
						});
					} else {
						btn.disabled = true;
						showInfo('Logging in...');
						
						ajaxCall('ict_ast_login_with_2fa', {
							username: state.username,
							password: state.password,
							wfls_token: ''
						}).then(function(res){
							if (res && res.ok) {
								location.reload();
							} else {
								btn.disabled = false;
								showError(res && res.msg ? res.msg : 'Login failed.');
							}
						}).catch(function(){
							btn.disabled = false;
							showError('Network error. Please try again.');
						});
					}
				} else {
					const checkoutForm = document.querySelector('form.checkout');
					if (checkoutForm) {
						const placeOrderBtn = document.querySelector('#place_order');
						if (placeOrderBtn) {
							placeOrderBtn.click();
						} else {
							checkoutForm.submit();
						}
					}
				}
			}
		});
	}

	function removeOriginalHeading(){
		const allHeadings = Array.from(document.querySelectorAll('h3')).filter(function(h){
			return h.textContent.trim() === 'Customer information' && !h.closest('#ict-checkout-login-box');
		});
		
		if (allHeadings.length > 0) {
			allHeadings[0].style.display = 'none';
		}
	}

	function init(){
		removeOriginalHeading();
		if (replaceCustomerInfoWithLoginBox()) {
			initLoginLogic();
		}
		
	}

	document.addEventListener('click', function(e){
		if (e.target && e.target.id === 'ast-customer-login-url') {
			e.preventDefault();
			const passRowEl = document.getElementById('ict_password_row');
			const passInp = document.getElementById('ict_login_password');
			const btn = document.getElementById('ict_login_button');
			const lostPwdLink = document.getElementById('ict_lost_password_link');
			const optionalMsg = document.getElementById('ict_optional_login_message');
			if (passRowEl) {
				const computedStyle = window.getComputedStyle(passRowEl);
				const isHidden = computedStyle.display === 'none' || 
				                computedStyle.visibility === 'hidden' ||
				                passRowEl.offsetParent === null;
				
				if (isHidden) {
					slideDown(passRowEl);
					if (btn) btn.textContent = 'Login';
					if (lostPwdLink) showElement(lostPwdLink);
					if (optionalMsg) slideDown(optionalMsg);
					if (passInp) {
						setTimeout(function(){
							passInp.focus();
						}, 350);
					}
				} else {
					slideUp(passRowEl);
					if (btn) btn.textContent = 'Continue';
					if (lostPwdLink) hideElement(lostPwdLink);
					if (optionalMsg) slideUp(optionalMsg);
				}
			}
		}
	});

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}

	const mo = new MutationObserver(function(){
		removeOriginalHeading();
		if (!document.getElementById('ict-checkout-login-box')) {
			if (replaceCustomerInfoWithLoginBox()) {
				initLoginLogic();
			}
		}
	});
	mo.observe(document.body, {childList:true, subtree:true});
})();
JS
    );
	},
	20
);

/**
 * Basic styling so the custom login box looks like Astra checkout.
 */
add_action(
	'wp_head',
	function () {
		if ( ! function_exists( 'is_checkout' ) || ! is_checkout() || is_user_logged_in() ) {
        return;
    }
    ?>
<style id="ict-ast-checkout-2step-2fa-styles">
#ict-checkout-login-box label {
    display: block;
}

#ict-checkout-login-box .input-text {
    width: 100%;
    box-sizing: border-box;
}

#ict-checkout-login-box .password-input-wrapper {
    position: relative;
    display: block;
}

#ict-checkout-login-box .password-input-wrapper .input-text {
    padding-right: 40px;
}

#ict-checkout-login-box .password-toggle {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    padding: 0;
    cursor: pointer;
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.ict-user-registered-message {
    color: #69bf29;
}

#ict-checkout-login-box .ict-login-actions {
    display: flex;
    align-items: center;
    /*gap: 12px;*/
}

#ict-checkout-login-box .ict-lost-password-link {
    margin-left: auto;
}

#ict-checkout-login-box .ict-optional-login-message {
    margin-top: 8px;
    /*font-size: 13px;*/
    /*color: #666666;*/
}
</style>
<?php
	}
);