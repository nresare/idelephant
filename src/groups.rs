use crate::error::IdentityError;
use crate::oauth::require_admin;
use crate::persistence::{Group, PersistenceService};
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/groups", get(list).post(create).delete(delete))
        .route("/groups/users", get(users))
        .route("/groups/members", post(add_member).delete(remove_member))
}

#[derive(Deserialize)]
struct CreateGroup {
    group_id: String,
    name: String,
}

#[derive(Deserialize)]
struct DeleteGroup {
    group_id: String,
}

#[derive(Deserialize)]
struct Membership {
    group_id: String,
    user_id: String,
}

#[derive(Serialize)]
struct User {
    user_id: String,
    email: String,
}

async fn list(
    session: Session,
    State(ps): State<PersistenceService>,
) -> Result<Json<Vec<Group>>, IdentityError> {
    require_admin(&session, &ps).await?;
    Ok(Json(ps.list_groups().await?))
}

async fn users(
    session: Session,
    State(ps): State<PersistenceService>,
) -> Result<Json<Vec<User>>, IdentityError> {
    require_admin(&session, &ps).await?;
    Ok(Json(
        ps.list_group_users()
            .await?
            .into_iter()
            .map(|(user_id, email)| User { user_id, email })
            .collect(),
    ))
}

fn validate_group(request: &CreateGroup) -> Result<(), IdentityError> {
    if request.group_id.is_empty()
        || request.group_id.len() > 64
        || !request
            .group_id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
    {
        return Err(IdentityError::BadRequest(
            "Group ID must be 1–64 lowercase letters, digits, hyphens or underscores".to_string(),
        ));
    }
    if request.name.trim().is_empty() || request.name.len() > 200 {
        return Err(IdentityError::BadRequest(
            "Group name must be 1–200 bytes and cannot be blank".to_string(),
        ));
    }
    Ok(())
}

async fn create(
    session: Session,
    State(ps): State<PersistenceService>,
    Json(request): Json<CreateGroup>,
) -> Result<StatusCode, IdentityError> {
    require_admin(&session, &ps).await?;
    validate_group(&request)?;
    ps.create_group(&request.group_id, request.name.trim())
        .await?;
    Ok(StatusCode::CREATED)
}

async fn delete(
    session: Session,
    State(ps): State<PersistenceService>,
    Json(request): Json<DeleteGroup>,
) -> Result<StatusCode, IdentityError> {
    require_admin(&session, &ps).await?;
    Ok(if ps.delete_group(&request.group_id).await? {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    })
}

async fn add_member(
    session: Session,
    State(ps): State<PersistenceService>,
    Json(request): Json<Membership>,
) -> Result<StatusCode, IdentityError> {
    change_membership(session, ps, request, true).await
}

async fn remove_member(
    session: Session,
    State(ps): State<PersistenceService>,
    Json(request): Json<Membership>,
) -> Result<StatusCode, IdentityError> {
    change_membership(session, ps, request, false).await
}

async fn change_membership(
    session: Session,
    ps: PersistenceService,
    request: Membership,
    add: bool,
) -> Result<StatusCode, IdentityError> {
    require_admin(&session, &ps).await?;
    Ok(
        if ps
            .set_group_membership(&request.group_id, &request.user_id, add)
            .await?
        {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        },
    )
}
