# idElephant 

idElephant aims to become the go-to Open Source identity provider implementation for organisations and individuals 
that wants to implement their own Single-Sign-On solution. At this point this is just a vision, and at most 
this project is an example implementation of the _Relying Party_ part of the 
[W3C Web Authentication](https://www.w3.org/TR/webauthn-2/) (webauthn) standard, 
but I have a plan and I think that the other pieces will come.

## Some design details

* This software is built in Rust, relying on the crates.io ecosystem when appropriate. 
* I use the [axum](https://github.com/tokio-rs/axum) web framework for the web parts
* I use an embedded [SurrealDB](https://surrealdb.com) for persistent storage, for now. I believe it should be 
  pretty straight forward to move the system to use a hosted or standalone SurrealDB instance instead.

## License

Licensed under either of the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or the
[MIT license](http://opensource.org/licenses/MIT) at your option.

### Contribution licensing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.