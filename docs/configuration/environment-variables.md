# Environment variables

Proksi can be configured using environment variables and **they will have higher priority over the config file**.&#x20;

They are mapped to the configuration file keys, always start with `PROKSI_` and can be used to override the default values. For nested keys, use the `__` character.

### Example:

For the key `service_name`, the environment variable `PROKSI_SERVICE_NAME` can used
For the key `worker_threads`, the environment variable `PROKSI_WORKER_THREADS` can be used
For the key `logging.level`, the environment variable `PROKSI_LOGGING__LEVEL` can be used (note the `__` separator due to the nested key)

For keys that accept a list of values, e.g. `routes`, the environment variable `PROKSI_ROUTES` can be used with a string value like this:

```bash
export PROKSI_ROUTES='[{host="example.com", upstreams=[{ip="10.0.1.24", port=3001}]'
```


### Full list

Below you can find a full list of the configuration keys and their corresponding environment variables.

| Key | Environment variable | Description |
| :--- | :--- | :--- |
| `service_name` | `PROKSI_SERVICE_NAME` | The name of the service |
| `worker_threads` | `PROKSI_WORKER_THREADS` | The number of worker threads |
| `daemon` | `PROKSI_DAEMON` | Whether the service should run as a daemon |
| `logging.level` | `PROKSI_LOGGING__LEVEL` | The log level |
| `logging.format` | `PROKSI_LOGGING__FORMAT` | The log format |
| `logging.path` | `PROKSI_LOGGING__PATH` | The path where we should write logs files |
| `logging.rotation` | `PROKSI_LOGGING__ROTATION` | The rotation policy of the log files |
| `lets_encrypt.enabled` | `PROKSI_LETS_ENCRYPT__ENABLED` | Whether lets encrypt should be enabled |
| `lets_encrypt.email` | `PROKSI_LETS_ENCRYPT__EMAIL` | The email address used for lets encrypt |
| `lets_encrypt.staging` | `PROKSI_LETS_ENCRYPT__STAGING` | Whether lets encrypt should be used in staging mode |
| `paths.lets_encrypt` | `PROKSI_PATHS__LETS_ENCRYPT` | The path where we should write the lets encrypt certificates |
| `docker.enabled` | `PROKSI_DOCKER__ENABLED` | Whether the docker service should be enabled |
| `docker.interval_secs` | `PROKSI_DOCKER__INTERVAL_SECS` | The interval (in seconds) to check for label updates |
| `docker.endpoint` | `PROKSI_DOCKER__ENDPOINT` | The docker endpoint to connect to the docker socket/api |
| `upstream.read_timeout_secs` | `PROKSI_UPSTREAM__READ_TIMEOUT_SECS` | Seconds allowed for the upstream read timeout |
| `upstream.write_timeout_secs` | `PROKSI_UPSTREAM__WRITE_TIMEOUT_SECS` | Seconds allowed for the upstream write timeout |
| `upstream.connection_timeout_secs` | `PROKSI_UPSTREAM__CONNECTION_TIMEOUT_SECS` | Seconds to wait while establishing new upstream connections |
| `upstream.total_connection_timeout_secs` | `PROKSI_UPSTREAM__TOTAL_CONNECTION_TIMEOUT_SECS` | Max seconds a connection may take end-to-end |
| `upstream.idle_timeout_secs` | `PROKSI_UPSTREAM__IDLE_TIMEOUT_SECS` | Seconds before an idle upstream connection is closed |
| `upstream.h2_ping_interval_secs` | `PROKSI_UPSTREAM__H2_PING_INTERVAL_SECS` | Ping interval for HTTP/2 connections |
| `upstream.max_h2_streams` | `PROKSI_UPSTREAM__MAX_H2_STREAMS` | Maximum concurrent HTTP/2 streams per upstream connection |
| `upstream.verify_cert` | `PROKSI_UPSTREAM__VERIFY_CERT` | Whether Pingora verifies upstream TLS certificates |
| `h2.max_concurrent_streams` | `PROKSI_H2__MAX_CONCURRENT_STREAMS` | Maximum HTTP/2 streams advertised to clients |
