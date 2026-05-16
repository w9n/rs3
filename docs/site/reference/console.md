# Console Reference

`rs3-console` is a read-only browser console for one gateway. It exists to make
the path-redacted admin facts easier to inspect without turning the gateway into a
management system.

## Data Flow

```text
Browser
  -> rs3-console GET /api/status
      -> rs3-server admin listener GET /admin/status
```

The browser authenticates to the console with `RS3_CONSOLE_BEARER_TOKEN`. The
console uses `RS3_GATEWAY_ADMIN_BEARER_TOKEN` only on the server side when it
calls the gateway admin listener.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /healthz` | Health check for the console process. |
| `GET /` and `/ui/*` | Static UI assets. |
| `GET /api/status` | Returns the gateway admin status report after console bearer authentication. |

The console has no persistent state and no mutating routes.

## Boundary

The console may display:

- gateway mode
- restore trust state and reason code
- v2 anchor sequence, commit digest, format generation, and version-binding state
- backend kind and retention capability
- anchor kind and external-anchor posture
- repository retention posture
- production-profile findings

Healthy privacy guardrails are silent in the main UI. If the gateway ever
reports that an admin surface exposes client-visible path browsing or secret
material, the console promotes that condition to a critical finding instead of
showing it as a normal option-like row.

The console must not display client-visible paths, Kubernetes object names,
configured backend bucket names, backend prefixes, configured core repository
IDs, access keys, wrapping keys, raw backend object IDs, or secret material.

## Runtime

Example:

```sh
RS3_CONSOLE_BIND=127.0.0.1:9083 \
RS3_CONSOLE_BEARER_TOKEN=<console-token> \
RS3_GATEWAY_ADMIN_URL=http://127.0.0.1:9082 \
RS3_GATEWAY_ADMIN_BEARER_TOKEN=<admin-token> \
cargo run -p rs3-console
```

The preview client accepts HTTP gateway admin origins. Run the console next to
the gateway over loopback, over a protected cluster-local network path, or
behind infrastructure that terminates TLS before the console-to-gateway hop.
