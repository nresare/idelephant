//! Adapt idElephant's registered clients to the shared OAuth client resolver.
use crate::error::IdentityError;
use crate::persistence::{OAuthClient, PersistenceService};
pub use idp_oauth::client_metadata::{ApplicationType, Client};
use idp_oauth::client_metadata::{
    ClientMetadataService, ClientRegistry, MetadataError, ResolveError,
};

/// Resolves registered clients and Client ID Metadata Documents.
#[derive(Clone, Default)]
pub struct ClientResolver {
    metadata: ClientMetadataService,
    /// Clients that tests resolve without fetching a metadata document.
    #[cfg(test)]
    seeded: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Client>>>,
}

impl ClientResolver {
    pub async fn resolve<R: ClientRegistry>(
        &self,
        registry: &R,
        id: &str,
    ) -> Result<Client, ResolveError<R::Error>> {
        #[cfg(test)]
        if let Some(client) = self.seeded.lock().unwrap().get(id) {
            return Ok(client.clone());
        }
        self.metadata.resolve(registry, id).await
    }

    #[cfg(test)]
    pub fn seed(&self, client: Client) {
        self.seeded
            .lock()
            .unwrap()
            .insert(client.client_id.clone(), client);
    }
}

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
