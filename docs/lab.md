# The Blink lab

A tiny local shop with deterministic tamper scenarios, used by the tests, the demo and the
evaluation harness. It needs the `[server]` extra and binds to 127.0.0.1 only.

```bash
python -m pip install "blink-checkout[server,capture]"
blink lab                                   # shop :8780, CDN :8781, sink :8782
blink lab --scenario overlay_form_added     # switch a running lab (or start one)
blink lab --list
```

| Port | Role |
|---|---|
| P | Shop: `/checkout`, the multi-step flow under `/shop` (below), `/staging/checkout` (auth), first-party `/static/app.js`, `/api/config`, `/__admin/scenario` |
| P+1 | Simulated third-party CDN: `/lib/widget.js` (loaded with SRI), `/lib/analytics.js` |
| P+2 | Localhost sink: `/collect` (beacons), `/frame`, `/pay` |

## Multi-step checkout (`/shop`)

Real payment pages usually need a cart and a session. The lab's `/shop` flow behaves the
same way, so journeys can be tested against it:

| Page | Behaviour |
|---|---|
| `/shop` | A product with `#add-to-cart` (a form posting to `/shop/cart/add`, which sets the `lab_cart` session cookie) |
| `/shop/cart` | The cart (`#cart-items`, `#go-to-details`), or "Your cart is empty" |
| `/shop/details` | Guest details: e-mail, name, postcode, country, terms, `#continue-to-payment` |
| `/shop/checkout` | The payment page (with every scenario applied). It redirects to `/shop/cart?empty=1` without a cart, and to `/shop/details` without guest details |

The lab never reads what a journey types: the details step only records *that* it happened.
`blink_visual.lab.lab_journey_target(origin)` returns a ready target whose journey runs the
whole flow ([journeys](journeys.md)). `/staging/checkout` serves the same checkout behind
basic auth (`lab` / `lab-staging-pass`) or the header `X-Lab-Token: lab-staging-token`, so
the per-target `auth:` setting can be tested.

## Scenarios

| Scenario | Change |
|---|---|
| `clean` | Known-good checkout with benign noise: rotating CSRF token, timestamp, promo banner, render id, session cookie |
| `new_third_party_script` | Adds a cross-origin script without SRI |
| `modified_approved_script` | Changes the content of first-party `app.js` |
| `inline_script_injected` | Adds an inert inline script inside the payment section |
| `csp_removed` | Drops the `Content-Security-Policy` header |
| `csp_weakened_unsafe_inline` | Adds `'unsafe-inline'` to `script-src` |
| `form_action_changed` | The card form posts to the sink origin |
| `hidden_iframe_added` | Adds a 1×1 off-screen iframe from the sink origin |
| `overlay_form_added` | Draws a fake card form (`action="#"`, no JavaScript) over the real one |
| `new_beacon_destination` | `/api/config` tells `app.js` to beacon `{"ping":1}` to the sink |
| `visual_payment_area_changed` | Changes the pay button styling (CSS only) |
| `noise_only` | Extra noise only (cache-busting pixel, request id and ETag headers); must produce no findings |

Switch scenarios over HTTP with `POST /__admin/scenario?scenario=NAME`.

## Safety rules

The lab triggers detection signals; it never demonstrates theft (`BUILD_PLAN.md` section 5).

- No fixture reads form field values, serializes payment inputs or sends user input.
- The only payload ever sent is the constant `{"ping":1}`, and only to the localhost sink.
- The only card number is the published test number 4242 4242 4242 4242, as placeholder text.
- The lab refuses to bind to non-loopback addresses.

`tests/test_lab.py` enforces these rules by scanning every lab script for forbidden patterns.
