---
description: Delegates auth decisions to an external process via Unix socket + Cap'n Proto RPC
---

# External Auth

This plugin sends inbound request data to an external service over a Unix domain socket using Cap'n Proto RPC.

The external service decides whether the request:

- continues to upstream (`pass`)
- is blocked (`block`)
- is redirected (`redirect`)

When the decision is `pass`, the external service can return an optional `upstreamValue` that Proksi forwards to upstream in a request header.

## Options

Plugin options are passed via `config`.

| Name | Description |
| --- | --- |
| `socket_path` | Required. Unix socket path for the external auth service |
| `timeout_ms` | Optional. RPC timeout in milliseconds (default `1000`) |
| `upstream_header` | Optional. Header name used to forward `upstreamValue` (default `x-proksi-auth-context`) |
| `on_error` | Optional. `deny` (default) or `allow` if RPC fails |
| `forward_headers` | Optional. Header allowlist to include in RPC request (lower latency than forwarding all headers) |
| `max_headers` | Optional. Hard cap on forwarded headers (default `32`) |

## Cap'n Proto RPC Schema

Proksi uses this schema:

```capnp
struct Header {
  name @0 :Text;
  value @1 :Text;
}

struct AuthRequest {
  method @0 :Text;
  host @1 :Text;
  path @2 :Text;
  query @3 :Text;
  clientIp @4 :Text;
  headers @5 :List(Header);
}

enum DecisionAction {
  pass @0;
  block @1;
  redirect @2;
}

struct AuthDecision {
  action @0 :DecisionAction;
  statusCode @1 :UInt16;
  upstreamValue @2 :Text;
  redirectLocation @3 :Text;
  responseBody @4 :Text;
}

interface ExternalAuthService {
  check @0 (request :AuthRequest) -> (decision :AuthDecision);
}
```

## Usage

```hcl
routes = [{
  host = "mywebsite.com"
  upstreams = [{ ip = "localhost", port = 3000 }]
  plugins = [{
    name = "external_auth"
    config = {
      socket_path = "/var/run/proksi-auth.sock"
      timeout_ms = 1200
      upstream_header = "x-auth-context"
      on_error = "deny"
      forward_headers = ["authorization", "cookie", "x-forwarded-for"]
      max_headers = 16
    }
  }]
}]
```
