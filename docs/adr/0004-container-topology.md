# ADR 0004: Container topology for the compose demo, and proxy settings by environment

- **Status:** accepted
- **Date:** 2026-11-27
- **Phase:** 7

## Context

`BUILD_PLAN.md` asks for a `docker-compose.yml` that runs `blink daemon`, `blink serve` and the
lab. Two safety rules from section 5 constrain it:

- the lab binds to 127.0.0.1 only (enforced in code, `lab/server.py`);
- the lab and dashboard bind to 127.0.0.1 by default.

In separate containers the daemon could not reach a loopback-only lab, and Docker can only
publish a port that the process binds on the container's network interface, not on its
loopback.

Separately, the capture-failure runbook must cover outbound proxies, but Chromium launched by
Playwright ignores `HTTPS_PROXY`, and Blink had no proxy setting.

## Decision

1. **One network namespace.** `daemon`, `serve` and the one-shot `setup` service use
   `network_mode: service:lab`. The lab keeps binding to 127.0.0.1, and the daemon scans it
   over loopback. No lab port is published.
2. **The dashboard binds 0.0.0.0 inside that namespace** so Docker can publish it. Blink treats
   that as a non-loopback bind, so **every page requires the token login** (Phase 5 security
   model). The port is published on the host's `127.0.0.1:8765` only. The demo reads the token
   with `docker compose exec serve cat /data/.blink/blink.token`.
3. Containers run as the image's non-root `pwuser`, with `read_only: true`, a `/tmp` tmpfs,
   `cap_drop: [ALL]` and `no-new-privileges`. All state is in the `/data` volume. `HOME=/tmp`,
   because Chromium writes its profile there.
4. **Proxy by environment:** `BLINK_PROXY` (server), `BLINK_PROXY_BYPASS`, and
   `BLINK_PROXY_USERNAME` / `BLINK_PROXY_PASSWORD` are passed to Chromium's launch. Credentials
   inside the URL are rejected so they cannot leak into logs or error messages. It is
   environment-only, not in `blink.yaml`, because proxies are a property of where Blink runs,
   not of the target, and `blink.yaml` is committed.

## Consequences

- The demo asks for a login that a pure-loopback `blink serve` would not. That is the
  intended behaviour, and it shows the model in action.
- Production deployments are not tied to this layout. Monitoring real payment pages needs no
  lab, so `daemon` and `serve` can run in ordinary networks behind TLS.
- A single proxy applies to all targets. Per-target proxies can be added to `blink.yaml`
  later if someone needs them.
