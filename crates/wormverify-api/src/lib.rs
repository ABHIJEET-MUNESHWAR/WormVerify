//! GraphQL API surface for the WormVerify off-chain service.

#![forbid(unsafe_code)]

pub mod schema;
pub mod state;

pub use schema::{build_schema, WormVerifySchema};
pub use state::{ConcreteEngine, ServiceState};

use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql_axum::{GraphQL, GraphQLSubscription};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;

async fn playground() -> impl IntoResponse {
    Html(playground_source(
        GraphQLPlaygroundConfig::new("/graphql").subscription_endpoint("/ws"),
    ))
}

/// Builds the axum router exposing the GraphQL endpoint, an interactive
/// playground, and a websocket subscription endpoint.
pub fn router(schema: WormVerifySchema) -> Router {
    Router::new()
        .route(
            "/graphql",
            get(playground).post_service(GraphQL::new(schema.clone())),
        )
        .route_service("/ws", GraphQLSubscription::new(schema))
}
