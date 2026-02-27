# Middleware interface

The middleware interface is designed to be simple and easy to use. It allows you to extend Proksi with new features and functionality.

## Middleware types

There are two facets of middleware:

- **Middleware**: These middleware are executed before the request is sent to the upstream server. They can modify the request or response, add or remove headers, or perform other actions.
- **Extension**: These middleware are executed after the request is sent to the upstream server. They can perform additional actions, such as modifying the response or performing custom logic.

## Middleware lifecycle

When the middleware is added to Proksi, it can choose to execute in one of two phases:

- **Request Filter**: Executed before the request is sent to the upstream server.
- **Response Filter**: Executed after the request is received from the upstream server.

## Middleware configuration

Middleware can be configured in the Proksi configuration file. The configuration file specifies the name of the middleware, its configuration options, and any other settings that are required for the middleware to function.

Here's an example of a middleware configuration in the Proksi configuration file:

```hcl
# You can define a reference to a middleware in the configuration file
my_github_oauth_middleware: &my_oauth_middleware
  name: "oauth2"
  config:
    client_id: "your_client_id"
    client_secret: "your_client_secret"
    provider: "github"
    jwt_secret: "your_jwt_secret"
    validations:
      - organizations: ["your_org"]

another_oauth_middleware: &another_oauth_middleware
  name: "oauth2"
  config:
    client_id: "another_client_id"
    client_secret: "another_client_secret"
    provider: "workos"
    jwt_secret: "another_jwt_secret"

# Route using the middleware
routes:
  - host: "example.com"
    middleware:
      - *my_oauth_middleware
  - host: "another.com"
    middleware:
      - *my_github_oauth_middleware # You can reuse the middleware reference anywhere
```

In this example, the middleware is named "oauth2" and it is configured with the following options:

- `client_id`: Your Oauth2 client ID.
- `client_secret`: Your Oauth2 client secret.
- `provider`: The Oauth2 provider (e.g., "github", "workos").
- `jwt_secret`: A secret key used to sign and verify JWT tokens.
- `validations`: A list of validations that the user must pass to be authorized.

Note that the `config` key is optional and can be omitted if the middleware does not require any configuration options.

## Middleware API

The middleware API is designed to be simple and easy to use. It allows you to extend Proksi with new features and functionality.

Here's an example of how to use the middleware API in your middleware:

```rust
struct MyMiddleware;

#[async_trait]
impl Middleware for MyMiddleware {
    async fn request_filter(
        &self,
        session: &mut Session,
        state: &mut RouterContext,
        config: &RouteMiddleware,
    ) -> Result<bool> {
        // Your logic here
        Ok(false)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        state: &mut RouterContext,
    ) -> Result<()> {
        // Your logic here
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        state: &mut RouterContext,
        config: &RouteMiddleware,
    ) -> Result<bool> {
        // Your logic here
        Ok(false)
    }

    fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        state: &mut RouterContext,
    ) -> Result<()> {
        // Your logic here
        Ok(())
    }
}
```
