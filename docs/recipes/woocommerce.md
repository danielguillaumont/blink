# Recipe: WooCommerce checkout journey

!!! warning "Adapt the selectors"
    This is a **template**. Themes, page builders and plugins (Elementor, CheckoutWC, Fluid
    Checkout...) change the markup. Run it against **staging** first, fix each selector with
    your browser's developer tools (or draft one with `blink record`), and keep `test_mode`
    off unless the store uses a test payment gateway.

WooCommerce's classic checkout needs a cart: `/checkout/` redirects to `/cart/` when the cart is
empty. This journey adds a product, fills the guest billing details and stops at the payment
step, without placing the order.

```yaml
targets:
  - name: woo-checkout
    url: https://staging.shop.example/product/sample-product/
    profiles: [desktop-chrome, mobile-safari-ish]
    payment_region: "#payment"
    wait_for: "#payment"
    timeout_s: 90
    masks: [".woocommerce-notices-wrapper"]
    test_data:
      email: "{{faker.email}}"
    journey:
      - click: "button.single_add_to_cart_button"
      - wait_for: ".woocommerce-message, .wc-block-components-notice-banner"
      - goto: /checkout/
      - wait_for: "form.checkout"
      - fill: {selector: "#billing_first_name", value: "{{faker.first_name}}"}
      - fill: {selector: "#billing_last_name", value: "{{faker.last_name}}"}
      - fill: {selector: "#billing_address_1", value: "{{faker.street}}"}
      - fill: {selector: "#billing_city", value: "{{faker.city}}"}
      - fill: {selector: "#billing_postcode", value: "{{canary.postcode}}"}
      - fill: {selector: "#billing_phone", value: "{{faker.phone}}"}
      - fill: {selector: "#billing_email", value: "{{test_data.email}}"}
      - wait_for: "#payment .payment_methods"
      - capture: payment
      # Never add the "Place order" button (#place_order) here. Blink refuses it unless the
      # target sets test_mode: true.
```

Notes:

- **Block checkout** (the WooCommerce Blocks / Cart and Checkout blocks) uses different
  markup, for example `.wc-block-checkout` and `#email`. Replace the selectors accordingly.
- **Hosted payment fields** (Stripe, Braintree, Adyen) render inside iframes. To act inside
  one, set `frame:` on the step, e.g. `frame: "iframe[name^=__privateStripeFrame]"`.
  Monitoring their scripts doesn't need any steps.
- If country or state selects trigger an AJAX refresh, add `wait_ms: 1000` after them.
