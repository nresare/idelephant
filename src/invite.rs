// A service that is used to generate invites to be sent to users

use crate::config::EmailConfig;
use crate::persistence::PersistenceService;
use crate::Fatal;
use anyhow::{anyhow, Context};
use handlebars::Handlebars;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::json;
use std::borrow::Cow;
use std::sync::Arc;

#[derive(Clone)]
pub struct InviteService {
    persistence: Arc<PersistenceService>,
    transport: Arc<AsyncSmtpTransport<Tokio1Executor>>,
    sender: Mailbox,
    register: Handlebars<'static>,
    origin: Cow<'static, str>,
}

impl InviteService {
    pub fn new(
        persistence: Arc<PersistenceService>,
        config: &EmailConfig,
        origin: Cow<'static, str>,
    ) -> Result<Self, Fatal> {
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(config.relay_host.as_str())
            .map_err(|e| Fatal::EmailTransport(e.into()))?;
        if let Some(user) = &config.username {
            let Some(password) = config.password()? else {
                return Err(Fatal::Other(anyhow!(
                    "Email config sets email but not password"
                )));
            };
            builder = builder.credentials(Credentials::new(user.clone(), password));
        }
        let sender_email = config.sender_email.as_str();
        let mut register = Handlebars::new();
        register.register_template_file("invite_plain", "email_templates/invite_email.txt.tmpl")
            .map_err(|e|anyhow!("Could not register email template: 'email_templates/invite_email.txt.tmpl': {}", e))?;
        register.register_template_file("invite_html", "email_templates/invite_email.html.tmpl")
            .map_err(|e|anyhow!("Could not register email template 'email_templates/invite_email.html.tmpl': {}", e))?;

        Ok(Self {
            persistence,
            transport: Arc::new(builder.build()),
            sender: sender_email.parse().map_err(|e| {
                anyhow!(
                    "Could not parse '{sender_email}' as an email address: {}",
                    e
                )
            })?,
            register,
            origin,
        })
    }

    pub async fn invite(&self, email: &String, admin: bool) -> Result<(), anyhow::Error> {
        let token = self.persistence.create_invite(email, admin).await?;

        let data = json!({
            "invite_url": format!("{}/invite/{}", self.origin, token.base64()),
        });

        let m = Message::builder()
            .from(self.sender.clone())
            .to(email.parse()?)
            .subject("Invitation to idElephant")
            .multipart(MultiPart::alternative_plain_html(
                self.register.render("invite_plain", &data)?,
                self.register.render("invite_html", &data)?,
            ))?;
        self.transport
            .send(m)
            .await
            .context(format!("Failed to send invite email to '{}'", email))?;
        Ok(())
    }
}
