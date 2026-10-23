# idElephant 

idElephant aims to become the go-to Open Source identity provider implementation for organisations and individuals 
that wants to implement their own Single-Sign-On solution. At this point this is just a vision, and at most 
this project is an example implementation of the _Relying Party_ part of the 
[W3C Web Authentication](https://www.w3.org/TR/webauthn-2/) (webauthn) standard, 
but I have a plan and I think that the other pieces will come.

## Some design details

* This software is built in Rust, relying on the crates.io ecosystem when appropriate. 
* I use the [axum](https://github.com/tokio-rs/axum) web framework for the web parts
* I use [SurrealDB](https://surrealdb.com) for persistent storage.
* Short-lived JWK signing keys are stored in the database and rotated every 8 hours. While this means 
  that sensitive information is stored in the database, the short lifetime of the keys somewhat mitigates
  this risk and enables us to have multiple idelephant instances running in parallel

## Local development 

Install the SurrealDB CLI and run:

```sh
./scripts/local-db.sh start
cargo run -- --bypass-authentication -c local-dev/idelephant.toml
```

The script starts a database on `127.0.0.1:8001`, creates a database user named
`idelephant`, and writes its password to `local-dev/idelephant-password`. The
generated config points to that file. It also creates a SurrealDB root administrator
named `local_admin`, whose password is in `local-dev/root-password`. These files and
the database are excluded from Git. Run `./scripts/local-db.sh stop` when finished.

To inspect the database as its administrator:

```sh
(cd local-dev && \
  SURREAL_USER=local_admin SURREAL_PASS="$(cat root-password)" \
  surreal sql --endpoint ws://127.0.0.1:8001 --namespace default --database idelephant)
```

With `--bypass-authentication`, open `http://127.0.0.1:8080/?user=root` to sign in as
the built-in app administrator. `/?user=alice@example.test` signs in as an existing
user with that email, or creates a non-admin test user on first use. The flag only
works with a loopback `origin` and database URI, and makes the app listen on
`127.0.0.1`.

## Shutdown

SIGTERM and SIGINT (Ctrl-C) stop the server gracefully for both HTTP and HTTPS.
The server logs the signal, stops accepting connections, and allows active requests
up to 25 seconds to finish before exiting. Keep the deployment termination grace
period longer than this deadline; the Kubernetes default is 30 seconds.

## Login session duration

Set the top-level `session_timeout` option to control how long a login
session lasts without activity:

```toml
session_timeout = "1d" # 24 hours
```

The default is `"1h"` (one hour). Use a positive duration such as `"30s"`,
`"15 minutes"`, `"12h"`, `"7d"`, or `"1h 30m"`, up to `4294967295` seconds.
Session activity renews the timeout. This controls the idElephant
login session; OAuth access tokens and ID tokens retain their own lifetimes.
Restart the server after changing this setting.

## HTTPS and HTTP/2

Set both top-level PEM paths in the application config to serve HTTPS on port 8443:

```toml
tls_cert_path = "tls/cert.pem"
tls_key_path = "tls/key.pem"
```

Relative paths resolve from the configuration file's directory. Supply a certificate
chain and its matching unencrypted private key. Incomplete settings or unreadable,
invalid, or mismatched files prevent startup. TLS advertises `h2` and `http/1.1`
through ALPN. Omit both paths to keep HTTP on port 8080. The authentication bypass
still binds only to loopback, using port 8443 when TLS is enabled.

`origin` remains the public URL used for authentication. For direct local HTTPS,
set it to `https://localhost:8443`. Restart after replacing the certificate files.

The `.deploy` website block sets `tls = true`, generating a cluster-local
certificate and mounting its Secret at `/tls`. The app reads `/tls/tls.crt` and
`/tls/tls.key`. Service port 443 targets container port 8443, and health checks use
HTTPS. The generated BackendTLSPolicy validates the service hostname against the
`cluster-local-ca` ConfigMap distributed to the labeled namespace.

## Managing app registrations

Sign in with an admin account and open **App registrations** from the admin navigation. You can
register apps with a unique client ID, a display name, and one redirect URI per line.
Existing apps can be edited or deleted; client IDs stay fixed when editing.
Deleting an app also revokes its stored access tokens, refresh tokens, authorization
codes, and consents.

The token endpoint accepts a client ID in the form body without authentication,
or as the username in HTTP Basic authentication. Any Basic client secret is
accepted and ignored, including an empty secret. Client IDs must still be
registered, and authorization code exchanges require the matching redirect URI
and S256 PKCE verifier. If both Basic and form client IDs are supplied, they must
match.

## MCP authorization

idElephant supports public OAuth clients using Client ID Metadata Documents
(CIMD), authorization code flow with S256 PKCE, and signed JWT access tokens.
Dynamic client registration is not implemented. Both
`/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`
advertise the issuer, endpoints, PKCE, and CIMD support. Authorization redirects
include the issuer in `iss`.

An MCP server must serve protected-resource metadata identifying itself and
idElephant's public `origin` as its authorization server, for example:

```json
{
  "resource": "https://tools.example.com/mcp",
  "authorization_servers": ["https://identity.example.com"],
  "scopes_supported": ["email"]
}
```

Publish this at the MCP server's `/.well-known/oauth-protected-resource` endpoint
(or the appropriate resource-specific well-known path), and return its URL in the
`resource_metadata` parameter of a `WWW-Authenticate: Bearer` challenge on HTTP 401.
The MCP server implements these endpoints and validates the bearer access token on
every protected request.

CIMD clients use their HTTPS metadata document URL as `client_id`. idElephant
fetches the document and checks its matching `client_id`, `client_name`, callback
URIs, and support for token authentication method `none`. It also recognizes the
plural `token_endpoint_auth_methods_supported` field, allowing `none` when it is
one of the client's supported methods. Signed client assertions (`private_key_jwt`)
are not supported. Metadata must be served directly, without redirects, from a
public HTTPS address. Fetches have time and size limits; cached documents expire
within five minutes, or earlier according to `Cache-Control`.

CIMD rejections are logged at warning level with a `client_id` and a specific
`reason`, distinguishing fetch failures from invalid metadata. URLs containing
credentials, queries, or fragments are redacted. Metadata bodies and OAuth
credentials are not logged by the CIMD resolver. At debug level, clients that
advertise additional grant types are logged when accepted for authorization-code
flow; unsupported token grant requests are still rejected.

Browser authorization failures show an HTML page explaining that the operation
failed, with the error detail and guidance for reporting a possible bug or
configuration issue. This includes invalid client metadata, malformed requests,
and errors while resuming authorization or recording consent. OAuth API endpoints
such as `/token` retain their protocol responses. Error pages are not cached, and
internal server details remain in the server logs.

Include the same `resource` in the authorization request and authorization-code
token exchange. It must be an absolute HTTPS URI without credentials, a query, or
a fragment. CIMD requests require it; manually registered OIDC clients can omit it
and receive tokens addressed to idElephant's `/userinfo` endpoint. Resource
identifiers are compared exactly, including paths and trailing slashes. Native CIMD
clients (`application_type: "native"`) may choose any port for an HTTP loopback
callback on `127.0.0.1`, `[::1]`, or `localhost`; the remaining URI must match
exactly. Token exchange must repeat the complete callback URI used in the
authorization request, including the selected port. Consent
is remembered separately for each user, client, and resource.

Request `email` to include the user's email, `groups` to include group names, and
`offline_access` for rotating refresh tokens. `openid` is optional for OAuth;
requesting it additionally returns an ID token addressed to the client. A resource
request that omits scopes defaults to `email`. Custom API scopes are not currently
supported. The MCP server applies its own permissions using the authenticated
user's identity.

Access tokens are ES256-signed JWTs with `typ: at+jwt`, a signing-key `kid`, and
claims `iss`, `sub`, `aud`, `client_id`, `iat`, `exp`, `jti`, and `scope`. Email and
groups are included only with their corresponding scopes. Use `sub` as the stable
account identifier; email can change. Keys are published at `/jwks.json`.

The MCP server must verify the signature using the discovered JWKS, allow only
ES256, require `typ: at+jwt`, check expiry, require the configured issuer, and
require its own exact resource identifier as the audience. Reject ID tokens and
tokens addressed to other MCP servers. Do not merely decode the JWT. Locally
validated JWTs remain usable until their one-hour expiry even after server-side
revocation; removing a client or refresh grant prevents future renewals. Resource
access tokens are not accepted by `/userinfo`.

Refresh requests may repeat the original resource or omit it to retain that
audience. They cannot switch resources. Configure the MCP server and idElephant
with HTTPS public URLs when connecting Claude or ChatGPT.

## Refresh tokens

Request `offline_access` to receive a refresh token after user consent. To renew access, POST a form to `/token` containing
`grant_type=refresh_token`, `client_id`, and `refresh_token`. The same Basic client
ID handling described above is supported. No redirect URI or PKCE verifier is
required for refresh requests.

Each successful refresh returns a new one-hour access token and a replacement
refresh token. Save the replacement before refreshing again. Refresh tokens expire
30 days after the initial authorization; rotation does not extend this deadline.
They work independently of the browser login session. Refresh responses do not
include a new ID token.

An optional `scope` field can reduce the granted scopes; omitted scopes retain the
current grant. Reduced scopes also apply to subsequent refreshes. Tokens are bound
to their client, resource, and an active user. Reusing a replaced refresh token
revokes that entire refresh-token family, requiring a new authorization. Previously
issued access tokens remain valid until their own expiry.

Only SHA-256 hashes of refresh tokens are stored in the database, including prior
hashes used for replay detection. The raw refresh token is returned to the client
and cannot be recovered from its stored hash.

## Managing groups

Admins can open **Groups** to create groups with a name and description, edit or delete
them, and add or remove existing users. Deleting a group removes its memberships but
does not delete its users.

OIDC clients may request the `groups` scope alongside `openid`. After consent, the
ID token contains a `groups` array of the user's current group names (including an
empty array when the user is not in any groups). The same claim is available from
`/userinfo` for access tokens granted the `groups` scope. Without that scope, the
claim is omitted. Membership is read when each response is generated, so an ID
token reflects membership at issuance time while `/userinfo` reflects current
membership.

## License

Licensed under either of the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or the
[MIT license](http://opensource.org/licenses/MIT) at your option.

### Contribution licensing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any
additional terms or conditions.
