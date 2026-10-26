use axum::{
    Router,
    extract::{MatchedPath, Request, State},
    http::HeaderMap,
    middleware::{self, Next},
    response::Response,
};
use opentelemetry::{
    Context, KeyValue,
    context::FutureExt,
    propagation::{Extractor, TextMapPropagator},
    trace::{SpanKind, Status, TraceContextExt, Tracer, TracerProvider},
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    trace::{Sampler, SdkTracer},
};
use std::{collections::HashSet, time::Duration};

pub use opentelemetry_sdk::trace::SdkTracerProvider;

/// OTLP/gRPC export settings, validated while deserializing application config.
#[derive(Clone, Debug)]
pub struct TracesConfig {
    pub endpoint: String,
    pub service_name: String,
    pub excluded_paths: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawTracesConfig {
    endpoint: String,
    service_name: Option<String>,
    #[serde(default)]
    excluded_paths: Vec<String>,
}

impl TracesConfig {
    /// Deserialize an optional table with the calling application's service name.
    pub fn deserialize_optional<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
        default_service_name: &str,
    ) -> Result<Option<Self>, D::Error> {
        use serde::Deserialize;
        Option::<RawTracesConfig>::deserialize(deserializer)?.map(|raw| {
            let endpoint = url::Url::parse(&raw.endpoint)
                .map_err(|_| "Invalid traces.endpoint; expected an absolute HTTP(S) gRPC endpoint")?;
            if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none()
                || !endpoint.username().is_empty() || endpoint.password().is_some()
                || !matches!(endpoint.path(), "" | "/") || endpoint.query().is_some() || endpoint.fragment().is_some() {
                return Err("Invalid traces.endpoint; use an HTTP(S) gRPC endpoint such as http://tempo:4317 without /v1/traces, credentials, query or fragment");
            }
            let service_name = raw.service_name.unwrap_or_else(|| default_service_name.into());
            if service_name.trim().is_empty() { return Err("Invalid traces.service-name; expected a non-empty string"); }
            if raw.excluded_paths.iter().any(|path| !path.starts_with('/') || path.contains('?') || path.contains('#')) {
                return Err("Invalid traces.excluded-paths; expected absolute URL paths without query or fragment");
            }
            Ok(Self { endpoint: raw.endpoint, service_name, excluded_paths: raw.excluded_paths })
        }).transpose().map_err(serde::de::Error::custom)
    }
}

pub fn provider(config: &TracesConfig) -> anyhow::Result<SdkTracerProvider> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.endpoint)
        .with_timeout(Duration::from_secs(2))
        .build()?;
    Ok(SdkTracerProvider::builder()
        .with_resource(
            Resource::builder()
                .with_service_name(config.service_name.clone())
                .build(),
        )
        .with_sampler(Sampler::AlwaysOn)
        .with_batch_exporter(exporter)
        .build())
}

pub async fn shutdown(provider: SdkTracerProvider) {
    // Exporting blocks; keep Tokio running so the gRPC transport can finish.
    match tokio::task::spawn_blocking(move || {
        provider.shutdown_with_timeout(Duration::from_secs(3))
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(%error, "could not flush traces during shutdown"),
        Err(error) => tracing::warn!(%error, "trace shutdown task failed"),
    }
}

#[derive(Clone)]
struct RequestTracing {
    tracer: SdkTracer,
    excluded_paths: HashSet<String>,
}

pub fn instrument<S: Clone + Send + Sync + 'static>(
    app: Router<S>,
    provider: &SdkTracerProvider,
    config: &TracesConfig,
) -> Router<S> {
    app.layer(middleware::from_fn_with_state(
        RequestTracing {
            tracer: provider.tracer("idp-server"),
            excluded_paths: config.excluded_paths.iter().cloned().collect(),
        },
        trace_request,
    ))
}

struct Headers<'a>(&'a HeaderMap);

impl Extractor for Headers<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.to_str().ok()
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|key| key.as_str()).collect()
    }
}

async fn trace_request(
    State(state): State<RequestTracing>,
    request: Request,
    next: Next,
) -> Response {
    if state.excluded_paths.contains(request.uri().path()) {
        return next.run(request).await;
    }
    let method = request.method().to_string();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned());
    let name = route
        .as_ref()
        .map_or_else(|| method.clone(), |route| format!("{method} {route}"));
    let parent = TraceContextPropagator::new().extract(&Headers(request.headers()));
    // Queries, headers, bodies and error messages can contain authentication secrets.
    let mut attributes = vec![KeyValue::new("http.request.method", method)];
    if let Some(route) = route {
        // Dynamic paths include invitation tokens (/accept/{token}). Only
        // record a concrete path when the router confirms it is static.
        if !route.contains('{') {
            attributes.push(KeyValue::new("url.path", request.uri().path().to_owned()));
        }
        attributes.push(KeyValue::new("http.route", route));
    }
    let span = state
        .tracer
        .span_builder(name)
        .with_kind(SpanKind::Server)
        .with_attributes(attributes)
        .start_with_context(&state.tracer, &parent);
    let context = Context::current_with_span(span);
    let response = next.run(request).with_context(context.clone()).await;
    let span = context.span();
    span.set_attribute(KeyValue::new(
        "http.response.status_code",
        i64::from(response.status().as_u16()),
    ));
    if response.status().is_server_error() {
        span.set_status(Status::error(""));
    }
    span.end();
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use opentelemetry::trace::{SpanId, TraceId};
    use opentelemetry_sdk::trace::InMemorySpanExporter;
    use tower::ServiceExt;

    fn config() -> TracesConfig {
        TracesConfig {
            endpoint: "http://127.0.0.1:4317".into(),
            service_name: "idelephant-test".into(),
            excluded_paths: vec!["/healthz".into()],
        }
    }

    #[tokio::test]
    async fn requests_capture_routes_status_and_parent_without_secrets() {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_sampler(Sampler::AlwaysOn)
            .with_simple_exporter(exporter.clone())
            .build();
        let app = instrument(
            Router::new()
                .route("/items/{id}", get(|| async { StatusCode::OK }))
                .route("/accept/{token}", get(|| async { StatusCode::OK }))
                .route("/fail", get(|| async { StatusCode::INTERNAL_SERVER_ERROR }))
                .route(
                    "/healthz",
                    get(|| async { StatusCode::OK }).post(|| async { StatusCode::OK }),
                )
                .route("/healthz/child", get(|| async { StatusCode::OK })),
            &provider,
            &config(),
        );
        for (method, path) in [
            ("GET", "/items/42?code=secret"),
            ("GET", "/fail"),
            ("GET", "/missing"),
            ("GET", "/healthz?query=secret"),
            ("POST", "/healthz"),
            ("GET", "/healthz/child"),
            ("GET", "/accept/secret"),
        ] {
            app.clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header(
                            "traceparent",
                            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                        )
                        .header("authorization", "Bearer secret")
                        .header("cookie", "session=secret")
                        .body(Body::from("secret"))
                        .unwrap(),
                )
                .await
                .unwrap();
        }
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 5);
        assert_eq!(spans[0].name, "GET /items/{id}");
        assert_eq!(spans[0].span_kind, SpanKind::Server);
        assert_eq!(
            spans[0].span_context.trace_id(),
            TraceId::from_hex("0123456789abcdef0123456789abcdef").unwrap()
        );
        assert_eq!(
            spans[0].parent_span_id,
            SpanId::from_hex("0123456789abcdef").unwrap()
        );
        assert_eq!(spans[0].status, Status::Unset);
        assert_eq!(spans[1].status, Status::error(""));
        assert_eq!(spans[2].name, "GET");
        assert_eq!(spans[2].status, Status::Unset);
        assert_eq!(spans[3].name, "GET /healthz/child");
        assert_eq!(spans[4].name, "GET /accept/{token}");
        for (span, code) in spans.iter().zip([200_i64, 500, 404, 200, 200]) {
            assert!(
                span.attributes
                    .contains(&KeyValue::new("http.response.status_code", code))
            );
            assert!(!format!("{span:?}").contains("secret"));
            assert!(span.end_time >= span.start_time);
        }
        shutdown(provider).await;
    }

    #[derive(Clone)]
    struct Collector(
        tokio::sync::mpsc::UnboundedSender<
            opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest,
        >,
    );

    #[tonic::async_trait]
    impl opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::TraceService
        for Collector
    {
        async fn export(
            &self,
            request: tonic::Request<
                opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest,
            >,
        ) -> Result<
            tonic::Response<
                opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceResponse,
            >,
            tonic::Status,
        > {
            self.0.send(request.into_inner()).unwrap();
            Ok(tonic::Response::new(Default::default()))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn grpc_export_and_shutdown_flush_reach_collector() {
        use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::TraceServiceServer;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(Collector(tx)))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = stop_rx.await;
                    },
                ),
        );
        let config = TracesConfig {
            endpoint,
            ..config()
        };
        let provider = provider(&config).unwrap();
        let app = instrument(
            Router::new().route("/", get(|| async { "ok" })),
            &provider,
            &config,
        );
        app.oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        shutdown(provider).await;
        let export = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let resource = &export.resource_spans[0];
        assert!(
            resource
                .resource
                .as_ref()
                .unwrap()
                .attributes
                .iter()
                .any(|attribute| {
                    attribute.key == "service.name"
                    && attribute.value.as_ref().unwrap().value
                        == Some(
                            opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(
                                "idelephant-test".into(),
                            ),
                        )
                })
        );
        assert_eq!(resource.scope_spans[0].spans[0].name, "GET /");
        assert_eq!(resource.scope_spans[0].spans[0].kind, 2);
        stop_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}
