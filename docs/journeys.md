# Journeys: reaching a real payment page

A target is one URL. On most real stores that isn't enough: `/checkout` redirects to the cart
when the cart is empty, and the card form only renders after the guest details step. A
**journey** is an ordered list of browser steps that Blink runs, in a fresh browser context, on
every capture to reach the payment page.

```yaml
targets:
  - name: checkout
    url: https://staging.shop.example/product/notebook   # where the journey starts
    profiles: [desktop-chrome, mobile-safari-ish]
    payment_region: "#payment"
    wait_for: "#checkout-form"
    test_data:
      email: "{{faker.email}}"
      password: "{{env.SHOP_TEST_PASSWORD}}"     # secrets only ever come from env vars
    journey:
      - click: "#add-to-cart"
      - wait_for: "#cart-items"
      - capture: cart                            # an extra, earlier page state
      - click: "#go-to-details"
      - fill: {selector: "#email", value: "{{test_data.email}}"}
      - fill: {selector: "#full-name", value: "{{canary.name}}"}
      - select: {selector: "#country", value: NL}
      - check: "#terms"
      - click: "#continue-to-payment"
      - assert_url: /checkout
      - wait_for: "#checkout-form"
      - capture: payment                         # the state Blink compares
```

Blink always loads `url` first, then runs the steps. Relative `goto` URLs resolve against
`url`.

## Steps

Each step is a one-key mapping. The short form `- click: "#sel"` and the long form
`- click: {selector: "#sel", timeout_s: 5}` are equivalent.

| Step | Fields | Does |
|---|---|---|
| `goto` | `url` | Navigate (an HTTP status of 400 or more fails the step) |
| `click` | `selector` | Click, then wait for any navigation to load |
| `fill` | `selector`, `value` | Type into a field (the value may use placeholders) |
| `select` | `selector`, `value` | Choose an option by value, or by label |
| `check` | `selector` | Tick a checkbox or radio |
| `press` | `key`, optional `selector` | Press a key (`Enter`, `Tab`...) in a field or the page |
| `wait_for` | `selector` | Wait until the element is visible |
| `wait_ms` | `ms` | Pause (max 60000) |
| `assert_visible` | `selector` | Fail unless the element becomes visible |
| `assert_url` | `url` | Fail unless the URL contains it (`re:` prefix for a regex) |
| `capture` | optional `name` | Snapshot this page state (see below) |
| `submit` | `selector` | Place the order: **only** with `test_mode: true` |

Every step also accepts:

- `timeout_s`: default 10, capped by the target's `timeout_s` budget;
- `frame`: the selector of an iframe to act in, for example hosted payment fields;
- `name`: a label for logs and findings.

Selectors are [Playwright selectors](https://playwright.dev/python/docs/other-locators): CSS,
`text=...`, `role=button[name="Pay"]` and so on.

## Capture states

`capture` marks the page states Blink records. Without any `capture` step, the final state is
recorded.

- The **last** `capture` is the snapshot's own state. Its DOM, forms, iframes, headers and
  screenshot are what the detectors compare with the baseline.
- **Earlier** captures record a screenshot and DOM hash in the snapshot's `journey.states`.
  Their scripts are added to the snapshot's script list, so a script that only runs on the cart
  page is still inventoried and checked (PCI DSS 6.4.3).
- Network requests, and scripts loaded at any point of the journey, are always included.
- Fields a journey fills are masked in screenshots automatically, because their values (canary
  and faker data) change on every run.

## Test data

| Placeholder | Value |
|---|---|
| `{{canary.pan}}`, `cvc`, `expiry`, `name`, `email`, `postcode`, `phone`, `token` | Per-capture canary values. The PAN is a Luhn-valid number in the `411111` range of the published Visa test card, never a real card; e-mails use the reserved `.invalid` domain |
| `{{faker.email}}`, `first_name`, `last_name`, `name`, `phone`, `street`, `city`, `postcode`, `country` | Plausible synthetic values, stable within one capture |
| `{{env.NAME}}` | An environment variable. This is the only way to pass a secret, and a missing variable is a configuration error |
| `{{test_data.KEY}}` | A value from the target's `test_data:` |

Placeholders are validated when `blink.yaml` loads. Snapshots and findings record step
descriptions (action and selector) but never resolved values. Values read from environment
variables are also redacted from the stored HAR. A secret typed into a visible field can still
appear in a screenshot, so use `type="password"` fields or `masks:` for it.

## Order safety

Journeys exist to **reach** the payment page, not to buy anything:

1. A `submit` step is only accepted when the target sets `test_mode: true`. Set it only for a
   store wired to a test payment gateway.
2. Without `test_mode`, a `click` or `press` whose selector looks like placing the order (place
   order, pay now, buy now, confirm payment, `[type=submit]`...) is **rejected when the config
   loads**. If a step only looks like one ("Continue to payment" on a button with
   `type=submit`), add `safe: true` to it.
3. At runtime, without `test_mode`, Blink installs a guard before any page script that blocks
   the submission of any form containing a card field (`autocomplete="cc-*"`, card, cvc, cvv,
   expiry). A blocked submission is counted in `journey.blocked_submissions` and reported as a
   warning.

## When a step fails

A failed step stops the journey. The run records a **`journey.step_failed`** finding (high)
with the step, its URL, the error and a screenshot of the page at that moment, and the run
exits **3**, because the payment page wasn't evaluated. The dashboard shows the screenshot on
the finding. The usual causes are a renamed selector, a new interstitial (cookie banner,
upsell) or a changed flow. An unexpected redirect on the way to payment can also be tampering.

A target **without** a journey that is redirected away from its URL (for example to
`/cart?empty=1`) also fails with a clear message, rather than baselining the wrong page:

```text
blink: http://127.0.0.1:8780/shop/checkout redirected to http://127.0.0.1:8780/shop/cart?empty=1
and '#checkout-form' never appeared: the payment page probably needs a cart, a session or
earlier checkout steps
hint: add a `journey:` to target 'checkout' that adds a product to the cart and fills the guest
details first (see docs/journeys.md)
```

## Drafting a journey with `blink record`

```bash
blink record https://staging.shop.example/product/notebook --name checkout --out draft.yaml
```

This opens Playwright's recorder. Click through to the payment page and close the window, and
Blink converts the recording into a draft `targets:` entry.

- Clicks that look like placing the order are removed, with a comment.
- Typed card numbers and e-mail addresses become `{{canary.pan}}` and `{{faker.email}}`. Other
  typed values are kept for you to review.
- Calls Blink doesn't understand are left as `# TODO` comments.

`blink record URL --from-file recorded.py` converts an existing codegen script instead
(no browser needed). Recording needs a desktop session.

Recipes for common platforms: [WooCommerce](recipes/woocommerce.md) ·
[Magento / Adobe Commerce](recipes/magento.md). Both are templates; adapt the selectors.
