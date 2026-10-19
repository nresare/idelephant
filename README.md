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
./local-dev/local-db.sh start
cargo run -- --bypass-authentication -c local-dev/idelephant.toml
```

The script starts a database on `127.0.0.1:8001`, creates a database user named
`idelephant`, and writes its password to `local-dev/idelephant-password`. The
checked in config points to that file. It also creates a SurrealDB root administrator
named `local_admin`, whose password is in `local-dev/root-password`. The passwords,
database data, logs, and process files are excluded from Git. Run
`./local-dev/local-db.sh stop` when finished.

To inspect the database as its administrator:

```sh
(cd local-dev && \
  SURREAL_USER=local_admin SURREAL_PASS="$(cat root-password)" \
  surreal sql --endpoint ws://127.0.0.1:8001 --namespace default --database idelephant)
```

With `--bypass-authentication` (or `bypass_authentication = true` in the config file),
open `http://127.0.0.1:8080/?user=root` to sign in as
the built-in app administrator. `/?user=alice@example.test` signs in as an existing
user with that email, or creates a non-admin test user on first use. Bypass mode only
works with a loopback `origin` and database URI, and makes the app listen on
`127.0.0.1`.

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
through ALPN. Omit both paths to keep HTTP on port 8080.

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
Deleting an app also revokes its stored access tokens, authorization codes, and consents.

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
