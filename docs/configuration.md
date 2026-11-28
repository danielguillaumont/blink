# `blink.yaml` reference

`blink init` writes a starter file. Paths are relative to the directory containing
`blink.yaml`. Unknown keys are rejected so that typos fail loudly. Pass `--config PATH` to any
command, or set `BLINK_CONFIG`, to use a file other than `./blink.yaml`.

```yaml
version: 1                       # configuration schema version
store: .blink                    # evidence store (git-ignored): blobs, SQLite index, keys
inventory: blink.inventory.yaml  # approved script inventory (commit this file)
rules: blink.rules.yaml          # optional severity rules, evaluated before the defaults

profiles:                        # optional custom browser profiles
  tablet:
    viewport: {width: 820, height: 1180}
    user_agent: "Mozilla/5.0 (iPad; ...)"
    is_mobile: true
    has_touch: true
    device_scale_factor: 1
    locale: en-US
    timezone: UTC

targets:
  - name: checkout               # lowercase letters, digits, - and _
    url: https://shop.example/checkout
    profiles: [desktop-chrome, mobile-safari-ish]
    payment_region: "#payment"   # CSS selector for the visual and DOM detectors
    wait_for: "#checkout-form"   # wait for this selector after network idle
    masks: [".timestamp", ".promo"]   # painted over in screenshots
    timeout_s: 30                # whole-capture budget; exceeding it exits 3
    settle_ms: 250               # pause after the page is ready
    normalize:
      strip_attributes: [nonce]  # removed from every element
      volatile_attributes:       # values replaced with "[volatile]"
        - selector: 'input[name="csrf_token"]'
          attributes: [value]
      volatile_text: [".timestamp", ".promo"]   # text replaced with "[volatile]"
      remove: ["#chat-widget"]   # elements removed entirely
      regexes:                   # applied last to the serialized DOM
        - pattern: 'build-[0-9a-f]{8}'
          replacement: 'build-<id>'
    visual:                      # Blink 1.0 engine on the payment-region screenshot
      threshold: 15              # max-channel difference that counts as changed (0-255)
      min_region_pixels: 25      # ignore connected changes smaller than this
      min_change_percent: 0.05   # ignore changes below this share of the region
```

See [detectors.md](detectors.md) for what each detector reports and how rules grade it, and
[operations.md](operations.md) for the top-level `schedule:` and `alerts:` sections (and the
per-target `schedule:` override).

## Built-in profiles

| Profile | Viewport | User agent |
|---|---|---|
| `desktop-chrome` | 1280 × 900 | Chrome on Windows |
| `mobile-safari-ish` | 390 × 844, mobile, touch | Safari on iPhone |

Capturing with more than one profile helps expose skimmers that cloak by user agent.

## Proxies and protected targets

Staging checkouts often sit behind basic auth or a bypass header, and some hosts can only reach
the internet through a proxy. Secrets are **never** written in `blink.yaml`: each one names an
environment variable that Blink reads at capture time. A missing variable is a configuration
error (exit 2) that names it.

```yaml
targets:
  - name: staging-checkout
    url: https://staging.shop.example/checkout
    proxy:                          # overrides BLINK_PROXY for this target
      server: http://proxy.internal:3128   # http, https or socks5; no credentials in the URL
      bypass: "localhost,.corp.example"
      username_env: PROXY_USER      # optional, both or neither
      password_env: PROXY_PASS
    auth:                           # one of:
      type: basic                   #   HTTP basic auth
      username_env: STAGING_USER
      password_env: STAGING_PASS
    # auth:
    #   type: header                #   a header token, e.g. a WAF or staging bypass token
    #   header: X-Staging-Token     #   default Authorization
    #   value_env: STAGING_TOKEN
    #   prefix: "Bearer "           #   optional, prepended to the value
```

- Auth is sent **only to the target's own origin** (scheme, host and port). Third-party script
  hosts never receive it; the lab test `tests/test_access.py` checks this on every run.
- The auth header name and every resolved secret value are redacted from the stored HAR, so
  they never reach snapshots, reports or evidence bundles.
- A profile may also set `proxy:` (for example a regional egress); a profile proxy wins over the
  target's, which wins over `BLINK_PROXY`.

## Determinism

Every capture uses a fresh browser context with the profile's viewport, user agent, locale and
timezone, `reducedMotion: reduce`, a light colour scheme, blocked service workers, and a
stylesheet that disables animations, transitions and the text caret while screenshotting.
Blink waits for the `load` event, then network idle (up to 10 s), then `wait_for`, then
`settle_ms`. Masked elements are painted a solid colour in both the full-page and the
payment-region screenshots.

Normalization keeps structure: a volatile attribute keeps its name and a volatile element keeps
its children, so a structural change such as an added input still changes the DOM hash.

## What is captured

| Artifact | Contents | Never contains |
|---|---|---|
| `screenshot`, `region_screenshot` | PNG, masks applied | — |
| `dom` | normalized HTML | raw CSRF tokens or other values you mark volatile |
| scripts | URL or inline digest, SHA-384, `integrity`, `crossorigin`, frame, initiator chain, body blob | — |
| `har` | URLs, methods, statuses, timings | cookie values, `Authorization`/`Cookie`/`Set-Cookie` values, request bodies, response bodies |
| headers | main-document response headers | `Set-Cookie` and credential headers |
| forms | action, method, input names, types and `autocomplete` | field values |
| iframes | src, geometry, visibility, off-screen flag, sandbox | — |
| cookies | name, domain, path, flags | values |
| TLS | subject, issuer, serial, SHA-256 fingerprint, validity, SANs, trust | — |
