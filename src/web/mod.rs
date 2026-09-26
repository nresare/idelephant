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
        registry.register_template("authorize", WebTemplates::compile("authorize.html.tmpl")?);
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

#[cfg(test)]
mod tests {
    use super::Templates;
    use serde_json::json;

    #[test]
    fn app_management_is_only_rendered_for_admins() {
        let templates = Templates::new().unwrap();
        for admin in [false, true] {
            let html = templates
                .render(
                    "index",
                    &json!({
                        "identity": { "email": "admin@example.com" }, "admin": admin,
                    }),
                )
                .unwrap();
            assert_eq!(html.contains("id=\"app-form\""), admin);
            assert_eq!(html.contains("/static/apps.js"), admin);
            assert_eq!(html.contains("id=\"group-form\""), admin);
            assert_eq!(html.contains("/static/groups.js"), admin);
        }
        let html = templates.render("index", &json!({})).unwrap();
        assert!(!html.contains("id=\"app-form\""));
    }
}
