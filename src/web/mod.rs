use crate::invite::Compile;
use crate::{AppState, Fatal};
use axum::extract::FromRef;
use handlebars::{Handlebars, RenderError};
use rust_embed::Embed;
use serde::Serialize;
use std::ops::Deref;
use std::sync::Arc;

#[derive(Clone)]
pub struct Templates {
    registry: Arc<Handlebars<'static>>,
}

impl Templates {
    pub fn new() -> Result<Self, Fatal> {
        let mut registry = Handlebars::new();
        registry.register_template("accept", WebTemplates::compile("accept.html.tmpl")?);
        registry.register_template("index", WebTemplates::compile("index.html.tmpl")?);
        Ok(Self {
            registry: Arc::new(registry),
        })
    }

    pub fn render<T>(&self, name: &str, data: &T) -> Result<String, RenderError>
    where
        T: Serialize,
    {
        self.registry.render(name, data)
    }
}

#[derive(Embed)]
#[folder = "web_templates"]
struct WebTemplates;

impl Compile for WebTemplates {}

impl FromRef<AppState> for Templates {
    fn from_ref(input: &AppState) -> Self {
        input.templates.deref().clone()
    }
}
