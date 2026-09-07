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

1. Install a local surrealdb. I installed mine with `brew install surrealdb/tap/surreal`
2. in a shell, start with `surreal start --user noa --pass secret surrealkv://$HOME/slask/devdb`
3. Create a database user by issuing the following commands:
   1. `surreal sql --user noa --pass secret`
   2. `use ns default db idelephant`
   3. `DEFINE USER idelephant ON DATABASE PASSWORD 'idelephant' ROLES OWNER`
   4. ctrl-d
4. Run `cargo run -- -c idelephant.toml`

## Managing app registrations

Sign in with an admin account to see **App registrations** on the home page. You can
register apps with a unique client ID, a display name, and one redirect URI per line.
Existing apps can be edited or deleted; client IDs stay fixed when editing.
Deleting an app also revokes its stored access tokens, authorization codes, and consents.

## Groups

Admins can create and delete groups and add or remove active users from the Groups
section on the home page. Each group has a fixed unique ID and a display name.
Membership does not change the user's idElephant admin privileges.

Apps request `scope=openid groups` to receive a `groups` claim containing an array
of group IDs in the ID token and `/userinfo` response. The claim is omitted without
that scope and is an empty array when the user has no memberships. Consent screens
explicitly describe sharing group memberships, and discovery advertises the scope
and claim. Memberships are read from the database at token issuance and on each
UserInfo request. Already issued ID tokens retain their claims until expiry.

## License

Licensed under either of the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or the
[MIT license](http://opensource.org/licenses/MIT) at your option.

### Contribution licensing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any
additional terms or conditions.
