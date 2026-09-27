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
