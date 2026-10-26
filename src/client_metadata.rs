//! Adapt idElephant's registered clients to the shared OAuth client resolver.
use crate::error::IdentityError;
use crate::persistence::{OAuthClient, PersistenceService};
pub use idp_oauth::client_metadata::{ApplicationType, Client, ClientMetadataService};
use idp_oauth::client_metadata::{ClientRegistry, MetadataError, ResolveError};

impl From<OAuthClient> for Client {
    fn from(client: OAuthClient) -> Self {
        Self {
            client_id: client.client_id,
            name: client.name,
            redirect_uris: client.redirect_uris,
            cimd: false,
            application_type: ApplicationType::Web,
        }
    }
}

impl ClientRegistry for PersistenceService {
    type Error = IdentityError;

    async fn find_client(&self, id: &str) -> Result<Option<Client>, Self::Error> {
        Ok(self.fetch_oauth_client(id).await?.map(Into::into))
    }
}

impl From<MetadataError> for IdentityError {
    fn from(error: MetadataError) -> Self {
        Self::OAuthDetailed {
            code: error.code,
            detail: error.detail,
        }
    }
}

impl From<ResolveError<IdentityError>> for IdentityError {
    fn from(error: ResolveError<IdentityError>) -> Self {
        match error {
            ResolveError::Registry(error) => error,
            ResolveError::Metadata(error) => error.into(),
        }
    }
}
