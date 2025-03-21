// A service that is used to generate invites to be sent to users

use anyhow::Result;
use crate::persistence::PersistenceService;

struct InviteService<'a> {
    persistence: &'a PersistenceService,
}

impl InviteService {
    fn new(persistence: &PersistenceService) -> Self {
        Self {persistence}
    }
    
    fn invite(&self, email: String) -> Result<()> {
        todo!()
    }
}

