use crate::error::IdentityError;
use crate::oauth::require_admin;
use crate::persistence::{Group, PersistenceService, UserSummary};
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

pub fn group_routes() -> Router<AppState> {
    Router::new()
        .route("/api/users", get(list_users))
        .route("/api/groups", get(list_groups).post(create_group))
        .route(
            "/api/groups/{id}",
            axum::routing::put(update_group).delete(delete_group),
        )
        .route(
            "/api/groups/{id}/members",
            axum::routing::post(add_member).delete(remove_member),
        )
}

#[derive(Deserialize)]
struct GroupRequest {
    name: String,
    description: String,
}

#[derive(Deserialize)]
struct MembershipRequest {
    subject_id: String,
}

#[derive(Serialize)]
struct GroupResponse {
    id: String,
    name: String,
    description: String,
    members: Vec<UserSummary>,
}

async fn list_users(
    session: Session,
    State(ps): State<PersistenceService>,
) -> Result<Json<Vec<UserSummary>>, IdentityError> {
    require_admin(&session, &ps).await?;
    Ok(Json(ps.list_users().await?))
}

async fn list_groups(
    session: Session,
    State(ps): State<PersistenceService>,
) -> Result<Json<Vec<GroupResponse>>, IdentityError> {
    require_admin(&session, &ps).await?;
    let groups = ps.list_groups().await?;
    let memberships = ps.list_group_memberships().await?;
    let users = ps.list_users().await?;
    let mut result = Vec::with_capacity(groups.len());
    for group in groups {
        let id = group.id()?;
        let mut members: Vec<UserSummary> = memberships
            .iter()
            .filter(|membership| membership.group_id == id)
            .filter_map(|membership| users.iter().find(|user| user.id == membership.subject_id))
            .cloned()
            .collect();
        members.sort_by(|a, b| a.email.cmp(&b.email));
        result.push(GroupResponse {
            id,
            name: group.name,
            description: group.description,
            members,
        });
    }
    Ok(Json(result))
}

fn validate_group(request: &GroupRequest) -> Result<(&str, &str), IdentityError> {
    let name = request.name.trim();
    let description = request.description.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(IdentityError::BadRequest(
            "Group name must be 1–80 characters".to_string(),
        ));
    }
    if description.is_empty() || description.chars().count() > 300 {
        return Err(IdentityError::BadRequest(
            "Group description must be 1–300 characters".to_string(),
        ));
    }
    Ok((name, description))
}

fn name_is_used(
    groups: &[Group],
    name: &str,
    except_id: Option<&str>,
) -> Result<bool, IdentityError> {
    for group in groups {
        if group.name.eq_ignore_ascii_case(name) && Some(group.id()?.as_str()) != except_id {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn create_group(
    session: Session,
    State(ps): State<PersistenceService>,
    Json(request): Json<GroupRequest>,
) -> Result<(StatusCode, Json<GroupResponse>), IdentityError> {
    require_admin(&session, &ps).await?;
    let (name, description) = validate_group(&request)?;
    if name_is_used(&ps.list_groups().await?, name, None)? {
        return Err(IdentityError::BadRequest(
            "A group with this name already exists".to_string(),
        ));
    }
    let group = ps.create_group(name, description).await?;
    Ok((
        StatusCode::CREATED,
        Json(GroupResponse {
            id: group.id()?,
            name: group.name,
            description: group.description,
            members: Vec::new(),
        }),
    ))
}

async fn update_group(
    Path(id): Path<String>,
    session: Session,
    State(ps): State<PersistenceService>,
    Json(request): Json<GroupRequest>,
) -> Result<StatusCode, IdentityError> {
    require_admin(&session, &ps).await?;
    let (name, description) = validate_group(&request)?;
    if ps.fetch_group(&id).await?.is_none() {
        return Ok(StatusCode::NOT_FOUND);
    }
    if name_is_used(&ps.list_groups().await?, name, Some(&id))? {
        return Err(IdentityError::BadRequest(
            "A group with this name already exists".to_string(),
        ));
    }
    ps.update_group(&id, name, description).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_group(
    Path(id): Path<String>,
    session: Session,
    State(ps): State<PersistenceService>,
) -> Result<StatusCode, IdentityError> {
    require_admin(&session, &ps).await?;
    Ok(if ps.delete_group(&id).await? {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    })
}

async fn add_member(
    Path(id): Path<String>,
    session: Session,
    State(ps): State<PersistenceService>,
    Json(request): Json<MembershipRequest>,
) -> Result<StatusCode, IdentityError> {
    require_admin(&session, &ps).await?;
    if ps.fetch_group(&id).await?.is_none() {
        return Ok(StatusCode::NOT_FOUND);
    }
    if ps.fetch_identity(&request.subject_id).await?.is_none() {
        return Err(IdentityError::BadRequest("Unknown user".to_string()));
    }
    if ps
        .list_group_memberships()
        .await?
        .iter()
        .any(|membership| membership.group_id == id && membership.subject_id == request.subject_id)
    {
        return Err(IdentityError::BadRequest(
            "User is already in this group".to_string(),
        ));
    }
    ps.add_group_member(&id, &request.subject_id).await?;
    Ok(StatusCode::CREATED)
}

async fn remove_member(
    Path(id): Path<String>,
    session: Session,
    State(ps): State<PersistenceService>,
    Json(request): Json<MembershipRequest>,
) -> Result<StatusCode, IdentityError> {
    require_admin(&session, &ps).await?;
    Ok(if ps.remove_group_member(&id, &request.subject_id).await? {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    })
}

#[cfg(test)]
mod tests {
    use super::group_routes;
    use crate::auth::IDENTITY;
    use crate::config::EmailConfig;
    use crate::invite::InviteService;
    use crate::oidc::OidcService;
    use crate::persistence::{mem_db, Credential, Identity, IdentityState, PersistenceService};
    use crate::register::RegistrationService;
    use crate::web::Templates;
    use crate::AppState;
    use axum::body::{to_bytes, Body};
    use axum::extract::{Query, State};
    use axum::http::{header, Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use chrono::Utc;
    use serde::Deserialize;
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tower::ServiceExt;
    use tower_sessions::Session;

    #[derive(Deserialize)]
    struct LoginQuery {
        id: String,
    }

    async fn login(
        Query(query): Query<LoginQuery>,
        session: Session,
        State(ps): State<PersistenceService>,
    ) -> Result<StatusCode, crate::error::IdentityError> {
        let identity = ps.fetch_identity(&query.id).await?.unwrap();
        session.insert(IDENTITY, identity).await?;
        Ok(StatusCode::NO_CONTENT)
    }

    #[tokio::test]
    async fn group_api_requires_admin_and_manages_members() -> anyhow::Result<()> {
        let db = mem_db().await?;
        let ps = Arc::new(PersistenceService::new(db.clone()));
        let admin_id = ps
            .persist_identity(Identity {
                email: "admin@example.com".to_string(),
                created: Utc::now(),
                admin: true,
                id: None,
                state: IdentityState::Active {
                    credentials: vec![Credential::new(b"id", b"key", -7, 0)],
                },
            })
            .await?;
        let user_id = ps
            .persist_identity(Identity {
                email: "user@example.com".to_string(),
                created: Utc::now(),
                admin: false,
                id: None,
                state: IdentityState::Active {
                    credentials: vec![Credential::new(b"id2", b"key2", -7, 0)],
                },
            })
            .await?;
        let state = AppState {
            ps: ps.clone(),
            is: Arc::new(InviteService::new(
                ps.clone(),
                &EmailConfig {
                    relay_host: "localhost".to_string(),
                    username: None,
                    password_file: None,
                    sender_email: "test@example.com".to_string(),
                },
                "http://localhost:8080",
            )?),
            templates: Arc::new(Templates::new()?),
            oidc: Arc::new(OidcService::new(
                "http://localhost:8080",
                ps.as_ref().clone(),
            )),
            rs: Arc::new(RegistrationService::new("http://localhost:8080")?),
        };
        let app = Router::new()
            .route("/test-login", get(login))
            .merge(group_routes())
            .layer(crate::make_session_layer(db))
            .with_state(state);

        let unauthorized = app
            .clone()
            .oneshot(Request::builder().uri("/api/groups").body(Body::empty())?)
            .await?;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let user_login = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/test-login?id={user_id}"))
                    .body(Body::empty())?,
            )
            .await?;
        let user_cookie = user_login.headers()[header::SET_COOKIE]
            .to_str()?
            .split(';')
            .next()
            .unwrap();
        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/groups")
                    .header(header::COOKIE, user_cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let admin_login = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/test-login?id={admin_id}"))
                    .body(Body::empty())?,
            )
            .await?;
        let admin_cookie = admin_login.headers()[header::SET_COOKIE]
            .to_str()?
            .split(';')
            .next()
            .unwrap();
        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/groups")
                    .header(header::COOKIE, admin_cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"name":"Engineering","description":"Builds the product"})
                            .to_string(),
                    ))?,
            )
            .await?;
        assert_eq!(created.status(), StatusCode::CREATED);
        let created: Value =
            serde_json::from_slice(&to_bytes(created.into_body(), usize::MAX).await?)?;
        let group_id = created["id"].as_str().unwrap();
        let member_uri = format!("/api/groups/{group_id}/members");
        let added = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&member_uri)
                    .header(header::COOKIE, admin_cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"subject_id":user_id}).to_string()))?,
            )
            .await?;
        assert_eq!(added.status(), StatusCode::CREATED);
        let listed = app
            .oneshot(
                Request::builder()
                    .uri("/api/groups")
                    .header(header::COOKIE, admin_cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(listed.status(), StatusCode::OK);
        let groups: Value =
            serde_json::from_slice(&to_bytes(listed.into_body(), usize::MAX).await?)?;
        assert_eq!(groups[0]["members"][0]["email"], "user@example.com");
        Ok(())
    }
}
