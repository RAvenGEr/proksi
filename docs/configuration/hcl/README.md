---
description: Configuration based on the Hashicorp Configuration Language
---

# HCL

## Configuration

Proksi can be configured using HCL ([HashiCorp Configuration Language](https://github.com/hashicorp/hcl/blob/main/hclsyntax/spec.md)). This is the recommended way to configure Proksi, as it is more human-readable and easier to work with than JSON or YAML as well as it offers `functions` that you can use throughout your configuration:

```bash
touch proksi.hcl
```

## Upstream defaults

The `upstream` block lets you tune the Pingora peer options that apply to every request. The defaults give you 360s read/idle timeouts, short connection/write timeouts, HTTP/2 keepalives, and TLS verification enabled:

```hcl
upstream {
  read_timeout_secs = 360
  write_timeout_secs = 60
  connection_timeout_secs = 10
  total_connection_timeout_secs = 20
  idle_timeout_secs = 360
  h2_ping_interval_secs = 60
  max_h2_streams = 2
  verify_cert = true
}
```

## H2 defaults

Use the `h2` block when you need to control the number of HTTP/2 streams advertised to clients. The default is `100`; set it to `0` to rely on Pingora’s own defaults.

```hcl
h2 {
  max_concurrent_streams = 100
}
```

```hcl
worker_threads = env("WORKER_THREADS")

server {
  https_address = "0.0.0.0:5143"
}

lets_encrypt {
  enabled = true
  email = env("LETS_ENCRYPT_EMAIL")
  staging = true
}

paths {
  lets_encrypt = env("LETS_ENCRYPT_PATH")
}

// You can split your websites into separate files
routes = [
  import("./sites/mywebsite.com.hcl"),
  import("./sites/myotherwebsite.co.uk.hcl")
]

// Or you can define them here
routes = [
  {
    host = "cdn.example.com"
    ssl_certificate = {
      // Useful for development
      self_signed_on_failure = true
    }
    upstreams = [{
      ip = "example.com"
      port = 443

      headers = {
        add = [
          { name = "Host", value = "example.com" },
          { name = "X-Proxy-For", value = "cdn.example.com" }
        ]
      }
    }]
  }
]
```
