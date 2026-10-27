# idFrog

idFrog brokers OAuth authorization for MCP servers using an upstream OpenID
Connect provider such as Microsoft Entra ID. It is a sibling application to
idElephant in this repository, with its own browser flow, configuration, and
in-memory grant state, optionally kept in DynamoDB instead. The `idp-oauth` and `idp-server` dependencies
provide shared protocol and HTTP infrastructure. Their versioned path dependencies
use the canonical sources in the repository's `crates/` directory for development;
independent consumers can use published crate versions without those paths.

Run the commands below from the idFrog directory (`cd idfrog` from the repository
root).

idFrog provides no local accounts, credentials, invitations, group administration,
or database of its own. Users authenticate and consent upstream. After validating the required
API permission, idFrog returns directly to the MCP client without another consent
screen.

## Entra setup

Create a **single-tenant Web application** with this redirect URI:

```text
https://idfrog.noa.re/oidc/callback
```

Use authorization code flow with certificate-based client authentication
(`private_key_jwt`). Implicit/hybrid grants and public client flows are not needed.
The example configuration contains app client ID
`73058fe2-56c3-42be-8fe1-e8f3e65ade9f`; set the tenant-specific v2 issuer and MCP
resource URLs for your deployment. Add a top-level block for each MCP:

```toml
[[resource]]
uri = "https://tool.example.com/mcp"
application-id = "0816f759-d89d-4319-a8d7-d88b5d751dc9"
```

idFrog derives the resource list and the scope prefix `api://<application-id>/`.
Use the default App ID URI `api://<application-id>` in the Entra API registration.
It requests `api://<application-id>/.default` with `openid profile email`, adding
`offline_access` for refresh grants. Configure the API's delegated permissions
and user/admin consent in Entra; no permission names are maintained in idFrog.
See [Microsoft's .default scope documentation](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc#the-default-scope).

Before issuing a code or refreshing a grant, idFrog validates the API token's
signature, issuer, exact application-ID audience, lifetime, client, tenant, and
user binding to the ID token. At least one delegated API scope must be present;
application roles alone are insufficient. Configure the API registration to issue
v2 access tokens (`requestedAccessTokenVersion = 2`) so `aud` is the application
ID rather than an App ID URI. Tokens with URI audiences are rejected.

Entra normally puts short names such as `Read Dashboard.Edit` in the signed `scp`
claim. The validated audience binds those names to the API. Qualified names must
match the configured prefix, which is stripped before forwarding. MCP tokens
contain the granted API scope names plus the client's requested OIDC scopes.
Unknown or ungranted client-requested API names are not invented as permissions.
The MCP decides which of those permissions each tool needs. Upstream credentials
stay inside idFrog, and downstream access tokens cannot outlive the API token.

### Certificate managed in Kubernetes

The [certificate manifest](kubernetes/entra-client-certificate.yaml) creates a
namespace, a namespace-scoped SelfSigned Issuer, and an RSA-2048 Certificate.
cert-manager creates and renews the `idfrog-entra-client` Secret with `tls.crt` and
`tls.key`. No client secret needs to be generated or copied from Entra.

```sh
kubectl apply -f kubernetes/entra-client-certificate.yaml
kubectl -n idfrog wait certificate/idfrog-entra-client --for=condition=Ready --timeout=120s
kubectl -n idfrog get secret idfrog-entra-client -o jsonpath='{.data.tls\.crt}' | base64 --decode > idfrog-entra-client.crt
```

Upload **only the public certificate** `idfrog-entra-client.crt` under the app
registration's **Certificates & secrets → Certificates**. The private key stays
in the Kubernetes Secret. Apply the [mount patch](kubernetes/deployment-certificate.patch.yaml)
to an existing Deployment with a container named `idfrog`:

```sh
kubectl -n idfrog patch deployment idfrog --type=strategic --patch-file kubernetes/deployment-certificate.patch.yaml
```

The example configuration reads `/var/run/idfrog/entra/tls.crt` and `tls.key`.
This certificate is separate from ingress/server TLS and idFrog's P-256 key for
signing MCP tokens. An existing organizational issuer can replace the example
SelfSigned Issuer by changing `issuerRef`.

idFrog validates the RSA key pair and certificate validity at startup, then loads
the credential into memory. Each authorization-code exchange and refresh sends a
fresh PS256 assertion with the certificate's SHA-256 thumbprint, the exact token
endpoint as audience, the app client ID as issuer and subject, a unique JWT ID,
and a maximum five-minute lifetime. Expired certificates cannot issue assertions.
See [Microsoft's certificate-credential format](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials).

cert-manager renewal does **not** register the new certificate in Entra. Before
restarting idFrog onto a renewed credential, upload its public certificate alongside
the old one, then roll out the restart before the old registered certificate
expires. Remove the old registration after cutover. idFrog keeps using its loaded
credential until restarted, so a Secret renewal alone does not switch credentials.
The example uses a one-year lifetime and renews thirty days before expiry.

If MCP servers need groups, configure the Entra app's ID tokens to include the
relevant group object IDs. Group IDs pass through unchanged; idFrog does not look
up display names, call Microsoft Graph, or enforce group admission. An overage
indication is rejected when the client requests group claims. Limit group
claims to relevant groups for this initial implementation.

Other OIDC providers must support the same resource-scoped delegated JWT grants,
an exact issuer, discovery and JWKS, code flow with S256 PKCE, and RS256 or ES256
signed tokens. Client authentication can use certificates or a shared secret. Upstream
refresh must return a fresh ID token; otherwise the downstream grant is revoked
and the user must authorize again.

## Configure and run

From the idFrog directory:

```sh
mkdir -p local-dev
cp idfrog.example.toml local-dev/idfrog.toml
cargo run -p idfrog -- generate-signing-key --output local-dev/signing-key.pem
```

Edit `local-dev/idfrog.toml` with the tenant and exact MCP resource URLs.
For local certificate authentication, point `certificate-file` and `private-key-file`
to an RSA certificate registered in Entra and its matching private key. For a generic
provider that requires a shared secret, replace the authentication table with:

```toml
[upstream.authentication]
method = "client-secret-post"
client-secret-file = "client-secret"
```

The secret file contains the secret value, with an optional trailing newline. Paths
resolve relative to the configuration file. The existing `local-dev/` Git exclusion
covers runtime files; these files are also excluded from Docker build contexts.
Restart after configuration or credential changes. Keep the MCP signing key persistent
and separate from the upstream client credential.

```sh
cargo run -p idfrog -- -c local-dev/idfrog.toml
```

The example listens on port 8080 behind an HTTPS ingress. Route
`https://idfrog.noa.re` to that listener. To serve TLS directly, configure both PEM
paths. `/healthz` is the readiness endpoint; the application starts serving after
configuration, signing-key loading, and upstream discovery succeed. SIGINT and
SIGTERM trigger bounded graceful shutdown, including during startup.

For local HTTP development, use an origin such as `http://localhost:8081` and set
`listen = "127.0.0.1:8081"`. Register that origin's `/oidc/callback` as an additional
Web callback upstream. Public deployments require HTTPS. Browser cookies are
HttpOnly, SameSite=Lax, and use Secure plus the `__Host-` prefix with HTTPS origins.

Build a container from the repository root so cargo-chef can see the workspace's
shared crate sources:

```sh
docker build -f idfrog/Dockerfile -t idfrog .
```

## Connect MCP clients and servers

An MCP server advertises `https://idfrog.noa.re` as its authorization server in
its OAuth protected-resource metadata and 401 challenge. Its exact resource
identifier must match a configured `[[resource]].uri`. The MCP server validates JWT
signatures using `/jwks.json`, requires ES256 and `typ: at+jwt`, and checks the
issuer, expiry, and its own exact resource audience. MCP permissions remain the
MCP server's responsibility.

The broker exposes `/authorize`, `/token`, `/jwks.json`, and both OAuth and OIDC
discovery documents. It supports public clients identified by HTTPS Client ID
Metadata Documents, or registered in `[[clients]]`. Native clients may vary the
port of a registered HTTP loopback callback; token exchange must repeat the actual
callback URI. Dynamic registration, confidential downstream clients, and
`/userinfo` are not implemented or advertised. `/token` accepts form parameters
with client authentication method `none`; it rejects Authorization headers.

Authorization and code exchange require the same `resource` and S256 PKCE.
OIDC scopes are `email`, `groups`, `openid`, and `offline_access`; an omitted
scope defaults to `email`. API permission names are determined by the signed
upstream grant rather than an idFrog allowlist. Email is omitted when the upstream provider supplies
none. Use `sub` as the account identifier: it is a stable digest of the upstream
issuer and subject, never an email address. An `openid` grant additionally returns
an ID token for the downstream client, with its own nonce. Tokens for MCP resources
are minted by idFrog; upstream bearer credentials are never passed to MCP clients.

## State and refresh behavior

By default, browser transactions, authorization codes, and refresh grants live
only in memory, so run **one replica**. Restarting invalidates pending flows and
refresh tokens; already issued access tokens remain valid until expiry when the
signing key is retained. To run several replicas or keep grants across restarts,
use DynamoDB as described below.

Transactions and codes expire after ten minutes. Access tokens last one hour.
Refresh-token families expire thirty days after authorization, and rotation does
not extend the deadline. Each refresh obtains and verifies a fresh upstream ID
token, rechecks subject and group admission, updates claims, and rotates the
broker's refresh token. A refresh may retain or reduce scopes and may not change
resource or client. Save the replacement token before refreshing again.

Replaying a spent token revokes its entire family, including a concurrent in-flight
refresh. An upstream failure also revokes the family, requiring a new authorization.
Refresh rechecks current API grants. Revoked permissions are removed, and a refresh
cannot introduce permissions outside the original downstream grant. A client can
also narrow its scopes explicitly; new permissions require a new authorization.

Only hashes of downstream codes and refresh tokens are retained. In-memory state
has fixed capacity limits, and each family permits up to 1,024 rotations before
requiring new authorization.

### DynamoDB state

Build with the `dynamodb` feature (`cargo build -p idfrog --features dynamodb`, or
`--build-arg FEATURES=dynamodb` for the container) and add:

```toml
[state]
backend = "dynamodb"
table = "idfrog"
region = "eu-west-1"
```

`region` is optional, as is `endpoint-url` for DynamoDB Local. Credentials and the
default region come from the standard AWS chain, such as environment variables,
EKS Pod Identity, IRSA, or an instance profile. Startup fails if the table cannot
be described. Create a table with a string partition key `pk`, and enable TTL on
`expires_at` so expired items are eventually deleted:

```sh
aws dynamodb create-table --table-name idfrog --billing-mode PAY_PER_REQUEST \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH
aws dynamodb update-time-to-live --table-name idfrog \
  --time-to-live-specification Enabled=true,AttributeName=expires_at
```

idFrog needs `dynamodb:DescribeTable`, `GetItem`, `PutItem`, `UpdateItem`, and
`DeleteItem` on the table. Reads are strongly consistent and ignore expired items
regardless of TTL. Conditional writes keep codes and transactions single-use and
detect refresh replay across replicas, with the same behavior and rotation limit
as in-memory state; DynamoDB state has no capacity limits.

Items hold the upstream refresh token, the user's claims, and pending PKCE
verifiers as JSON, so restrict access to the table and consider a customer-managed
KMS key. Downstream codes and refresh tokens are still stored only as hashes.

The signing key persists separately from grant state. Keep it stable across
restarts. This version publishes one key; replacing it invalidates previously
issued tokens. Upstream signing-key changes are picked up by fresh discovery at
login completion and refresh. A provider without `auth_time` uses its initial ID
token issuance time as the broker's authentication-time fallback.

## Development

```sh
cargo fmt --all --check
cargo test -p idfrog --locked
cargo clippy -p idfrog --all-targets --locked --no-deps --features dynamodb
```

To run the integration tests against DynamoDB Local instead of memory, start it on
port 8000 and run:

```sh
IDFROG_TEST_DYNAMODB_ENDPOINT=http://localhost:8000 cargo test -p idfrog --features dynamodb
```

The integration tests run both OAuth legs against a local provider with signed ID
tokens. They cover claim and signature validation, resource and redirect binding,
browser-bound state, automatic callback redirects, code single-use, refresh rotation
and replay races, and updated group admission. Certificate tests verify PS256 signatures, certificate thumbprints,
assertion audiences and lifetimes, and fresh assertions for code exchange and refresh.
They require loopback sockets, with no Entra credentials or database; each test
creates its own table when run against DynamoDB Local.

Each HTTP request emits one completion line at INFO level with its method, path,
status, and latency. Both applications use compact logs without module targets,
request IDs, or HTTP versions. Failures in that request include the operation and a specific
reason, such as a missing delegated scope, audience mismatch, or invalid nonce.
Entra token-exchange failures include recognized OAuth error names and numeric
AADSTS codes. Logs exclude query strings, headers, bodies, tokens, user claims,
and raw provider error descriptions. `RUST_LOG=idfrog=info,idp_server=info,idp_oauth=warn` enables
these diagnostics and is the default filter.

Optional traces use the same OTLP/gRPC exporter as idElephant:

```toml
[traces]
endpoint = "http://tempo.tempo.svc:4317"
excluded-paths = ["/healthz"]
```

The default service name is `idfrog`; override it with `service-name`. Incoming
W3C trace context is preserved. Spans contain method, matched route, status, and
duration; query strings, credentials, and dynamic path values are excluded.
Pending spans are flushed when the process shuts down, including startup failure
or interruption. Omit the table to disable exporting.
