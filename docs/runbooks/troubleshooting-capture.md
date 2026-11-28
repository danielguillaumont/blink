# Runbook: troubleshooting capture failures

A capture failure means Blink could not load the payment page: `blink scan` exits **3**, the
daemon retries and then records a `schedule.capture_failed` finding (high). Repeated failures
become a `schedule.missed_evaluation` finding once the allowed gap is exceeded, and that is a
PCI DSS 11.6.1 problem in its own right, so treat these as incidents.

## 1. Read the error

```bash
blink scan --profile desktop-chrome        # the error and hint are printed
blink alerts list --state open             # capture_failed / missed_evaluation alerts
```

| Message | Usual cause | Go to |
|---|---|---|
| `target unreachable: … (net::ERR_NAME_NOT_RESOLVED)` | DNS from where Blink runs | §2 |
| `… (net::ERR_CONNECTION_REFUSED / ERR_CONNECTION_TIMED_OUT)` | Firewall, wrong port, egress blocked, proxy required | §2, §3 |
| `… (net::ERR_PROXY_CONNECTION_FAILED / ERR_TUNNEL_CONNECTION_FAILED)` | Proxy address or credentials | §3 |
| `… (net::ERR_CERT_AUTHORITY_INVALID / ERR_CERT_COMMON_NAME_INVALID / ERR_CERT_DATE_INVALID)` | TLS: private CA, wrong host name, expired certificate | §4 |
| `timed out after 30s loading …` | Slow page, a `wait_for` selector that never appears, bot challenge | §5, §6 |
| `cannot launch Chromium` | Browser not installed or missing system libraries | §7 |

## 2. Network reachability

Test from **the same host or container** Blink runs on, not your laptop:

```bash
curl -sSI https://staging.example.com/checkout          # DNS, TCP, TLS, HTTP status
docker compose exec daemon python3 -c "import urllib.request as u; print(u.urlopen('https://staging.example.com/checkout', timeout=10).status)"
```

Fix the route (security group, egress rules, VPN, DNS) rather than working around it in
Blink.

## 3. Outbound proxy

Chromium does not read `HTTPS_PROXY`. Configure Blink's browser explicitly:

```bash
export BLINK_PROXY=http://proxy.internal:3128
export BLINK_PROXY_BYPASS="localhost,127.0.0.1,.corp.example"   # optional
export BLINK_PROXY_USERNAME=svc-blink                           # optional
export BLINK_PROXY_PASSWORD=...                                 # from your secret store
```

Credentials in the URL itself are rejected, so that they never end up in logs. A TLS-inspecting
proxy also needs its CA trusted (§4).

`BLINK_PROXY` applies to every target. To use a different proxy for one target (or one
profile), set `proxy:` on it in `blink.yaml`; see
[configuration.md](../configuration.md#proxies-and-protected-targets).

## 4. TLS errors

Blink has no "ignore certificate errors" switch, on purpose: a monitor that accepts any
certificate would happily monitor an attacker's page.

- **Expired or wrong-name certificate:** fix the certificate. A customer's browser would warn
  too.
- **Private CA (staging, TLS-inspecting proxy):** add the CA to Chromium's trust store for the
  user Blink runs as. On Linux Chromium uses NSS:

  ```bash
  mkdir -p "$HOME/.pki/nssdb"
  certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password      # once
  certutil -d "sql:$HOME/.pki/nssdb" -A -t "C,," -n corp-ca -i corp-ca.pem
  ```

  In the container `HOME` is `/tmp` (the root filesystem is read-only). Build a derived image
  that adds the CA, or mount an NSS database there.

## 5. Timeouts and slow pages

- Raise `timeout_s` on the target (default 30, max 300) in `blink.yaml`.
- `wait_for` must match an element that appears on **every** load. A selector that only exists
  after a consent banner is dismissed will time out; point it at the payment form container.
- `settle_ms` (default 250) is extra time after `wait_for` for late scripts. Raise it if
  late-loading scripts flap between "added" and "removed".
- The daemon retries (`schedule.retries`, `schedule.retry_backoff`) before it records a
  failure. Transient blips do not need more retries; persistent ones need a fix.

## 6. Bot protection and WAFs

Payment pages often sit behind bot management, which may serve Blink a challenge page, a block
page or a different script set.

- Symptoms: timeouts on `wait_for`, a baseline whose screenshot shows a challenge, or scripts
  that flip on every run.
- **Do not try to evade bot protection.** Ask the team that owns the WAF to allowlist Blink's
  egress IP (or a header your WAF can match) for the payment page path, and document that
  exception in the WAF configuration.
- Check the baseline screenshot (dashboard → Runs → finding, or the `screenshot` blob) before
  trusting a baseline.

## 7. Browser problems

```bash
python -m playwright install chromium            # add --with-deps on Linux for system libraries
blink capture TARGET --profile desktop-chrome    # one capture, no comparison
```

In Docker, use the published image (it is built on the official Playwright image) and give the
container `shm_size: 256m` or more, because Chromium crashes with the 64 MB default.

## 8. After the fix

1. `blink scan TARGET` by hand and confirm exit 0 or 1, not 3.
2. Resolve the `capture_failed` and `missed_evaluation` alerts with a note saying what was
   fixed (`blink alerts resolve ID --note "egress rule restored, CHG-123"`).
3. The gap stays visible in the evaluation log of the next `blink report`. Explain it to the
   assessor rather than hiding it.
