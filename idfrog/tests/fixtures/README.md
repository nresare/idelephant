These publicly committed credentials are test-only fixtures for the mock OIDC
client. The RSA-2048 PKCS8 key matches the self-signed X.509v3 certificate and is
not used by any deployment. Production credentials are issued by cert-manager.

`test-only-provider-key.pem` is a separate RSA-2048 PKCS8 key that the mock OIDC
provider signs RS256 tokens with, and that tests use as a key not matching the
certificate. Committing it avoids slow RSA key generation in unoptimized test builds.
