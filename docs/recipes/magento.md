# Recipe: Magento / Adobe Commerce checkout journey

!!! warning "Adapt the selectors"
    This is a **template** for the Luma theme's one-page checkout. Hyvä, PWA Studio and custom
    themes use different markup. Run it against **staging** first, fix each selector, and keep
    `test_mode` off unless the store uses a test payment method.

Magento's `/checkout/` redirects to the cart when the cart is empty, and the payment step only
renders after the shipping step. Magento is the classic Magecart target, so this journey stops
on the payment step where the card form and its scripts load.

```yaml
targets:
  - name: magento-checkout
    url: https://staging.shop.example/sample-product.html
    profiles: [desktop-chrome, mobile-safari-ish]
    payment_region: "#checkout-payment-method-load"
    wait_for: "#checkout-payment-method-load"
    timeout_s: 120
    masks: [".page.messages"]
    test_data:
      email: "{{faker.email}}"
    journey:
      - wait_for: "#product-addtocart-button:not([disabled])"
      - click: "#product-addtocart-button"
      - wait_for: ".message-success"
      - goto: /checkout/
      - wait_for: "#customer-email"
      - fill: {selector: "#customer-email", value: "{{test_data.email}}"}
      - fill: {selector: "input[name=firstname]", value: "{{faker.first_name}}"}
      - fill: {selector: "input[name=lastname]", value: "{{faker.last_name}}"}
      - fill: {selector: "input[name='street[0]']", value: "{{faker.street}}"}
      - fill: {selector: "input[name=city]", value: "{{faker.city}}"}
      - fill: {selector: "input[name=postcode]", value: "{{canary.postcode}}"}
      - select: {selector: "select[name=country_id]", value: "NL"}
      - fill: {selector: "input[name=telephone]", value: "{{faker.phone}}"}
      - wait_ms: 1500                       # shipping rates load over AJAX
      - check: "input[name^=ko_unique]"     # the first shipping method
      - click: "button.continue"            # "Next": goes to the payment step, places no order
      - wait_for: "#checkout-payment-method-load"
      - capture: payment
      # Never add "Place Order" (button.checkout). Blink refuses it unless the target sets
      # test_mode: true.
```

Notes:

- Knockout renders the checkout after page load, so the `wait_for` steps matter more than on
  server-rendered stores. Raise `timeout_s` on slow staging hosts.
- Magento skimmers often hide in `/static/` bundles and in CMS blocks loaded only on the
  checkout. A journey that really reaches the payment step is what puts those scripts in the
  inventory.
