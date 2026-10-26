# idp-oauth

OAuth/OIDC building blocks for idElephant and idFrog. The crate has no dependency
on either application, a database, or a web framework.

- `client_metadata` resolves registered clients through a required `ClientRegistry`,
  falling back to public HTTPS Client ID Metadata Documents. It includes metadata
  validation, bounded caching, SSRF protections, and native loopback redirect matching.
  `NoRegisteredClients` supports deployments accepting only metadata-document clients.
  Registry failures propagate instead of falling back to metadata.
- `discovery` provides serializable authorization-server metadata. Its defaults
  describe idElephant's endpoint layout; applications must advertise only the
  scopes, grant types, and client authentication methods they implement.
- `protocol` validates authorization-code requests, exact resource identifiers,
  client/redirect bindings, S256 challenges, and allowed scopes. Applications pass
  an explicit `AuthorizationPolicy` to choose their resource requirement and a
  `ScopePolicy`: a static supported set, or resource-defined scope names whose
  grants the application must validate before issuance. It also provides constant-time PKCE verification and redirect construction.
- `token` issues ES256 access and ID tokens from a `Principal`, an explicit
  `SigningKey`, and an issuance time. Access-token email and group disclosure follows
  the granted scopes. ID-token requests specify group disclosure and the original
  authentication time. `mint_access_token_until` bounds a downstream token by an
  upstream authorization deadline. Keys expose their public JWK for verification.

The caller must authenticate the principal and satisfy its authorization and
consent policy before minting tokens. It owns authentication, stable subject mapping, current user/group claims,
HTTP endpoints, sessions, authorization codes, refresh-token replay detection,
consent, and signing-key storage and rotation. This crate is not a standalone
OAuth authorization server or an upstream OIDC login client.

The `test-support` feature enables validated metadata cache seeding for application
protocol tests without network access. Leave it disabled for production builds.

Metadata diagnostics use the `idp_oauth::client_metadata` tracing target.

Run `cargo test -p idp-oauth` for tests independent of idElephant and its database.
