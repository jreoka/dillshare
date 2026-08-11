use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::header::CONTENT_TYPE,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{any, delete, get, post, put},
    Json, Router,
};
use base64::Engine;
use std::net::SocketAddr;
mod storage;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

async fn url_restriction_middleware(
    axum::extract::Extension(allowed_origin): axum::extract::Extension<Option<String>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    if let Some(origin) = allowed_origin {
        let expected = webauthn_rs::prelude::Url::parse(&origin)
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        let host = req
            .headers()
            .get(axum::http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .ok_or(axum::http::StatusCode::FORBIDDEN)?;
        let authority = host
            .parse::<axum::http::uri::Authority>()
            .map_err(|_| axum::http::StatusCode::FORBIDDEN)?;
        let host_matches = expected
            .host_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(authority.host()));
        let port_matches = authority.port_u16().map_or_else(
            || expected.port().is_none(),
            |port| expected.port_or_known_default() == Some(port),
        );

        if !host_matches || !port_matches {
            tracing::warn!(
                host,
                allowed_origin = origin,
                "Rejected unexpected Host header"
            );
            return Err(axum::http::StatusCode::FORBIDDEN);
        }

        if let Some(request_origin) = req.headers().get(axum::http::header::ORIGIN) {
            let request_origin = request_origin
                .to_str()
                .map_err(|_| axum::http::StatusCode::FORBIDDEN)?;
            let parsed = webauthn_rs::prelude::Url::parse(request_origin)
                .map_err(|_| axum::http::StatusCode::FORBIDDEN)?;
            if parsed.origin() != expected.origin() {
                tracing::warn!(
                    request_origin,
                    allowed_origin = origin,
                    "Rejected unexpected Origin header"
                );
                return Err(axum::http::StatusCode::FORBIDDEN);
            }
        }
    }

    Ok(next.run(req).await)
}

#[derive(Clone)]
struct AppState {
    storage: storage::Storage,
    bucket: String,
    jwt_secret: Vec<u8>,
    webauthn: std::sync::Arc<webauthn_rs::Webauthn>,
    presign_ttl: std::time::Duration,
    share_expiry_secs: i64,
    upload_session_max_secs: i64,
    max_share_bytes: i64,
}

#[tokio::main]
async fn main() {
    // Load .env file if it exists
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dillshare=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load S3 Configuration
    let configured_bucket = std::env::var("AWS_S3_BUCKET")
        .or_else(|_| std::env::var("S3_BUCKET"))
        .ok();
    if configured_bucket.is_none()
        && (std::env::var("AWS_ACCESS_KEY_ID").is_ok() || std::env::var("AWS_ENDPOINT_URL").is_ok())
    {
        panic!("AWS_S3_BUCKET or S3_BUCKET environment variable is required");
    }
    let bucket = configured_bucket
        .clone()
        .unwrap_or_else(|| "local-testing-bucket".to_string());

    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());

    if let Ok(endpoint) = std::env::var("AWS_ENDPOINT_URL") {
        tracing::info!("Using custom S3 endpoint URL: {}", endpoint);
        config_loader = config_loader.endpoint_url(endpoint);
    }

    let config = config_loader.load().await;
    let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&config);

    if let Ok(force_path_style) = std::env::var("AWS_S3_FORCE_PATH_STYLE") {
        if force_path_style == "true" {
            tracing::info!("Forcing S3 path-style addressing.");
            s3_config_builder = s3_config_builder.force_path_style(true);
        }
    }

    let storage = if configured_bucket.is_some() {
        let s3_client = aws_sdk_s3::Client::from_conf(s3_config_builder.build());
        storage::Storage::S3(s3_client)
    } else {
        tracing::warn!(
            "No S3 bucket configured. Running in memory mode; direct file transfers are disabled."
        );
        storage::Storage::Memory(std::sync::Arc::new(tokio::sync::Mutex::new(
            storage::MemoryBackend::default(),
        )))
    };

    if storage.supports_presigning() {
        tracing::info!("Validating S3 connection to bucket '{}'...", bucket);
        match storage.list_objects(&bucket, None, Some(1)).await {
            Ok(_) => tracing::info!("S3 connection verified successfully."),
            Err(error) => panic!(
                "S3 bucket validation failed ({error}). Check credentials, region, endpoint, and bucket permissions."
            )
        }
    }

    initialize_admin_roles(&storage, &bucket)
        .await
        .unwrap_or_else(|error| panic!("Failed to initialize account roles: {error}"));

    // Get JWT secret from environment or load/generate in S3
    let jwt_secret = match std::env::var("JWT_SECRET") {
        Ok(secret_str) if secret_str.len() >= 32 => secret_str.into_bytes(),
        Ok(_) => panic!("JWT_SECRET must contain at least 32 bytes"),
        Err(_) => load_or_create_jwt_secret(&storage, &bucket, "config/jwt_secret.bin")
            .await
            .unwrap_or_else(|error| panic!("Failed to load or persist JWT secret: {error}")),
    };

    let rp_id = std::env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let origin_str =
        std::env::var("RP_ORIGIN").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let rp_origin = webauthn_rs::prelude::Url::parse(&origin_str).expect("Invalid RP_ORIGIN URL");
    let builder =
        webauthn_rs::WebauthnBuilder::new(&rp_id, &rp_origin).expect("Invalid Webauthn builder");
    let builder = builder.rp_name("DillShare");
    let webauthn = std::sync::Arc::new(builder.build().expect("Invalid Webauthn config"));

    let presign_ttl_secs = std::env::var("DILLSHARE_PRESIGN_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(300)
        .clamp(60, 900);
    let share_expiry_days = std::env::var("DILLSHARE_EXPIRE_DAYS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(90)
        .clamp(1, 3650);
    let upload_session_max_hours = std::env::var("DILLSHARE_PARTIAL_TIMEOUT_HOURS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(12)
        .clamp(1, 168);
    let max_share_bytes = std::env::var("DILLSHARE_MAX_SHARE_BYTES")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(100 * 1024 * 1024 * 1024)
        .clamp(1024 * 1024, 5 * 1024 * 1024 * 1024 * 1024);

    let state = AppState {
        storage: storage.clone(),
        bucket: bucket.clone(),
        jwt_secret,
        webauthn,
        presign_ttl: std::time::Duration::from_secs(presign_ttl_secs),
        share_expiry_secs: share_expiry_days * 24 * 60 * 60,
        upload_session_max_secs: upload_session_max_hours * 60 * 60,
        max_share_bytes,
    };

    // Spawn background cleanup worker (runs every hour)
    tokio::spawn(run_cleanup_worker(storage, bucket));

    // Setup routes
    let app = Router::new()
        // API routes
        .route("/api/upload/init", post(upload_init))
        .route("/api/upload/:uuid/presign", post(upload_presign))
        .route(
            "/api/upload/:uuid/multipart/init",
            post(upload_multipart_init),
        )
        .route(
            "/api/upload/:uuid/multipart/part-url",
            post(upload_multipart_part_url),
        )
        .route(
            "/api/upload/:uuid/multipart/complete",
            post(upload_multipart_complete),
        )
        .route("/api/upload/:uuid/finish", post(upload_finish))
        .route("/api/upload/:uuid/abort", post(upload_abort))
        .route("/api/upload/:uuid/ping", post(upload_ping))
        .route("/api/share/:uuid", get(get_share).delete(delete_share))
        .route("/api/share/:uuid/file/*filename", get(download_file))
        .route("/api/share/:uuid/file-url/*filename", get(get_download_url))
        // Service worker for streaming decrypted media preview
        .route("/sw.js", get(serve_service_worker))
        // Self-hosted vendored frontend assets (embedded at compile time so the
        // binary runs fully offline with no CDN dependency for jszip, fflate,
        // streamsaver or the Plus Jakarta Sans webfont).
        .route("/assets/streamsaver.js", get(serve_asset_streamsaver))
        .route("/assets/streamsaver-sw.js", get(serve_asset_streamsaver_sw))
        .route(
            "/assets/streamsaver-mitm.html",
            get(serve_asset_streamsaver_mitm_html),
        )
        .route("/assets/jszip.js", get(serve_asset_jszip))
        .route("/assets/fflate.js", get(serve_asset_fflate))
        .route("/assets/marked.js", get(serve_asset_marked))
        .route(
            "/assets/fonts-inline.css",
            get(serve_asset_fonts_inline_css),
        )
        // Authentication routes
        .route("/api/register", post(register_user))
        .route("/api/login", post(login_user))
        .route(
            "/api/user/shares",
            get(get_user_shares).post(save_user_shares),
        )
        .route(
            "/api/user/profile",
            get(get_user_profile).post(save_user_profile),
        )
        .route("/api/user/password", put(user_change_password))
        .route("/api/user", delete(user_delete_account))
        // Passkey routes
        .route("/api/passkey/register_start", post(passkey_register_start))
        .route(
            "/api/passkey/register_finish",
            post(passkey_register_finish),
        )
        .route("/api/passkey/auth_start", post(passkey_auth_start))
        .route("/api/passkey/auth_finish", post(passkey_auth_finish))
        .route("/api/user/passkeys", get(get_user_passkeys))
        .route(
            "/api/user/passkeys/:id",
            delete(delete_user_passkey).put(rename_user_passkey),
        )
        .route("/api/user/sessions", get(get_user_sessions))
        .route(
            "/api/user/sessions/:id",
            delete(revoke_user_session).put(rename_user_session),
        )
        .route(
            "/api/user/2fa/setup",
            get(setup_2fa_init).post(setup_2fa_confirm),
        )
        .route("/api/user/2fa", delete(disable_2fa))
        // Admin routes (authorized by the signed-in account role)
        .route("/api/admin/stats", get(admin_get_stats))
        .route("/api/admin/share/:uuid", delete(admin_delete_share))
        .route("/api/admin/user/:username", delete(admin_delete_user))
        .route("/api/admin/user/:username/role", put(admin_set_user_role))
        .route(
            "/api/admin/user/:username/sessions",
            get(admin_get_user_sessions),
        )
        .route(
            "/api/admin/user/:username/sessions/:id",
            delete(admin_revoke_user_session),
        )
        // Static assets/routing (all fallback to SPA index.html)
        .route("/", get(serve_index))
        .route("/shares", get(serve_index))
        .route("/share/:uuid", get(serve_index))
        .route("/admin", get(serve_index))
        .route("/profile", get(serve_index))
        .route("/sessions", get(serve_index))
        // Never turn an unknown API call into a successful HTML response.
        .route("/api/*path", any(api_not_found))
        .fallback(serve_index)
        // API payloads are JSON/encrypted profile data; file bytes go directly to S3.
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let allowed_url = std::env::var("URL").ok().map(|value| {
        let parsed = webauthn_rs::prelude::Url::parse(&value)
            .unwrap_or_else(|_| panic!("URL must be a valid absolute http(s) URL"));
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            panic!("URL must contain only an http(s) origin (for example https://example.com)");
        }
        parsed.origin().ascii_serialization()
    });

    let app = if let Some(url) = allowed_url.clone() {
        use axum::http::HeaderValue;
        use tower_http::cors::Any;
        let origin = url
            .parse::<HeaderValue>()
            .expect("validated URL origin must be a valid header value");
        app.layer(
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods(Any)
                .allow_headers(Any),
        )
    } else {
        app.layer(CorsLayer::permissive())
    };

    let app = app
        .layer(axum::middleware::from_fn(url_restriction_middleware))
        .layer(axum::Extension(allowed_url));

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8000);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Dill Share server running at http://localhost:{}", port);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}

#[derive(serde::Deserialize)]
pub struct AuthStartPayload {
    pub username: Option<String>,
}

async fn passkey_register_start(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid token".into()))?;

    let user_unique_id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, username.as_bytes());

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user_unique_id, &username, &username, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let state_key = format!("users/{}/passkey_reg.json", username);
    let state_json = serde_json::to_vec(&reg_state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .storage
        .put_object(
            &state.bucket,
            &state_key,
            state_json,
            Some("application/json"),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(ccr))
}

async fn passkey_register_finish(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<webauthn_rs::prelude::RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid token".into()))?;

    let state_key = format!("users/{}/passkey_reg.json", username);
    let state_bytes = state
        .storage
        .get_object_bytes(&state.bucket, &state_key)
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "No registration session found".into(),
            )
        })?;
    let reg_state: webauthn_rs::prelude::PasskeyRegistration = serde_json::from_slice(&state_bytes)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid state".into()))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&payload, &reg_state)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let passkeys_key = format!("users/{}/passkeys.json", username);
    let mut passkeys: Vec<webauthn_rs::prelude::Passkey> = match state
        .storage
        .get_object_bytes(&state.bucket, &passkeys_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => vec![],
    };
    let credential_id = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(passkey.cred_id());
    let index_key = format!("passkey_index/{}", credential_id);
    if passkeys.iter().any(|existing| {
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(existing.cred_id()) == credential_id
    }) {
        return Err((
            StatusCode::CONFLICT,
            "Passkey is already registered".to_string(),
        ));
    }
    if passkeys.len() >= MAX_PASSKEYS_PER_ACCOUNT {
        return Err((
            StatusCode::CONFLICT,
            format!("At most {MAX_PASSKEYS_PER_ACCOUNT} passkeys may be registered"),
        ));
    }
    passkeys.push(passkey);

    let passkeys_json = serde_json::to_vec(&passkeys)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .storage
        .put_object(
            &state.bucket,
            &passkeys_key,
            passkeys_json,
            Some("application/json"),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = state
        .storage
        .put_object(
            &state.bucket,
            &index_key,
            username.as_bytes().to_vec(),
            None,
        )
        .await;

    let _ = state.storage.delete_object(&state.bucket, &state_key).await;

    Ok(Json(serde_json::json!({"success": true})))
}

async fn passkey_auth_start(
    State(state): State<AppState>,
    Json(payload): Json<AuthStartPayload>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let username_opt = payload
        .username
        .map(|username| username.trim().to_string())
        .filter(|username| !username.is_empty());
    if username_opt
        .as_deref()
        .is_some_and(|username| !is_valid_username(username))
    {
        return Err((StatusCode::BAD_REQUEST, "Invalid username".to_string()));
    }

    if let Some(username) = &username_opt {
        let passkeys_key = format!("users/{}/passkeys.json", username);
        let passkeys: Vec<webauthn_rs::prelude::Passkey> = match state
            .storage
            .get_object_bytes(&state.bucket, &passkeys_key)
            .await
        {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => return Err((StatusCode::BAD_REQUEST, "User has no passkeys".into())),
        };

        if passkeys.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "User has no passkeys".into()));
        }

        let (rcr, auth_state) = state
            .webauthn
            .start_passkey_authentication(passkeys.as_slice())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let session_id = uuid::Uuid::new_v4().to_string();
        let state_key = format!("auth_sessions/{}.json", session_id);
        let state_json = serde_json::to_vec(&auth_state)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        state
            .storage
            .put_object(
                &state.bucket,
                &state_key,
                state_json,
                Some("application/json"),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(Json(serde_json::json!({
            "rcr": rcr,
            "session_id": session_id
        })))
    } else {
        let (rcr, auth_state) = state
            .webauthn
            .start_discoverable_authentication()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let session_id = uuid::Uuid::new_v4().to_string();
        let state_key = format!("auth_sessions/{}.json", session_id);
        let state_json = serde_json::to_vec(&auth_state)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        state
            .storage
            .put_object(
                &state.bucket,
                &state_key,
                state_json,
                Some("application/json"),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(Json(serde_json::json!({
            "rcr": rcr,
            "session_id": session_id
        })))
    }
}

#[derive(serde::Deserialize)]
pub struct AuthFinishPayload {
    pub username: Option<String>,
    pub session_id: Option<String>,
    pub totp_code: Option<String>,
    pub auth: webauthn_rs::prelude::PublicKeyCredential,
}

async fn passkey_auth_finish(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<AuthFinishPayload>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let username_opt = payload
        .username
        .as_deref()
        .map(str::trim)
        .filter(|username| !username.is_empty());
    if username_opt.is_some_and(|username| !is_valid_username(username)) {
        return Err((StatusCode::BAD_REQUEST, "Invalid username".to_string()));
    }
    let is_discoverable = username_opt.is_none();
    let session_id = payload
        .session_id
        .as_deref()
        .filter(|session_id| is_canonical_uuid(session_id))
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid auth session".to_string()))?;
    let state_key = format!("auth_sessions/{}.json", session_id);

    let state_bytes = state
        .storage
        .get_object_bytes(&state.bucket, &state_key)
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "No auth session found".into()))?;

    let (username, auth_res) = if is_discoverable {
        let auth_state: webauthn_rs::prelude::DiscoverableAuthentication =
            serde_json::from_slice(&state_bytes)
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid state".into()))?;

        // Find username by cred_id
        let cred_id_b64 = payload.auth.id.clone();
        let index_key = format!("passkey_index/{}", cred_id_b64);

        let found_username = if let Ok(bytes) = state
            .storage
            .get_object_bytes(&state.bucket, &index_key)
            .await
        {
            String::from_utf8(bytes).unwrap_or_default()
        } else {
            // fallback scan
            let mut found = String::new();
            if let Ok(users) = state
                .storage
                .list_objects(&state.bucket, Some("users/"), None)
                .await
            {
                for u in users {
                    if u.key.ends_with("/passkeys.json") {
                        if let Ok(b) = state.storage.get_object_bytes(&state.bucket, &u.key).await {
                            let pks: Vec<webauthn_rs::prelude::Passkey> =
                                serde_json::from_slice(&b).unwrap_or_default();
                            if pks.iter().any(|pk| {
                                base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(pk.cred_id())
                                    == cred_id_b64
                            }) {
                                let parts: Vec<&str> = u.key.split('/').collect();
                                if parts.len() == 3 {
                                    found = parts[1].to_string();
                                    let _ = state
                                        .storage
                                        .put_object(
                                            &state.bucket,
                                            &index_key,
                                            found.as_bytes().to_vec(),
                                            None,
                                        )
                                        .await;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            found
        };

        if found_username.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "User not found for this passkey".into(),
            ));
        }

        let passkeys_key = format!("users/{}/passkeys.json", found_username);
        let passkeys: Vec<webauthn_rs::prelude::Passkey> = match state
            .storage
            .get_object_bytes(&state.bucket, &passkeys_key)
            .await
        {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => vec![],
        };
        let discoverable_keys: Vec<webauthn_rs::prelude::DiscoverableKey> =
            passkeys.into_iter().map(|p| p.into()).collect();

        let auth_res = state
            .webauthn
            .finish_discoverable_authentication(&payload.auth, auth_state, &discoverable_keys)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

        (found_username, auth_res)
    } else {
        let auth_state: webauthn_rs::prelude::PasskeyAuthentication =
            serde_json::from_slice(&state_bytes)
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid state".into()))?;
        let auth_res = state
            .webauthn
            .finish_passkey_authentication(&payload.auth, &auth_state)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
        (username_opt.unwrap().to_string(), auth_res)
    };

    let passkeys_key = format!("users/{}/passkeys.json", username);
    let mut passkeys: Vec<webauthn_rs::prelude::Passkey> = match state
        .storage
        .get_object_bytes(&state.bucket, &passkeys_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => vec![],
    };

    for pk in passkeys.iter_mut() {
        if pk.cred_id() == auth_res.cred_id() {
            pk.update_credential(&auth_res);
            break;
        }
    }
    let passkeys_json = serde_json::to_vec(&passkeys)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    state
        .storage
        .put_object(
            &state.bucket,
            &passkeys_key,
            passkeys_json,
            Some("application/json"),
        )
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;

    // Check 2FA before finalizing
    let user_key = format!("users/{}.json", username);
    let user_bytes = state
        .storage
        .get_object_bytes(&state.bucket, &user_key)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "User not found".to_string()))?;

    let user_json: serde_json::Value = serde_json::from_slice(&user_bytes).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid user data".to_string(),
        )
    })?;

    let totp_enabled = user_json
        .get("totp_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if totp_enabled {
        let totp_secret = user_json
            .get("totp_secret")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some(code) = &payload.totp_code {
            if !verify_totp_code(totp_secret, &username, code)? {
                return Err((StatusCode::FORBIDDEN, "INVALID_2FA".to_string()));
            }
        } else {
            return Err((StatusCode::FORBIDDEN, "2FA_REQUIRED".to_string()));
        }
    }

    let _ = state.storage.delete_object(&state.bucket, &state_key).await;

    let session_id = uuid::Uuid::new_v4().to_string();
    let expiry = 0;

    let token = generate_token(&username, &state.jwt_secret, expiry, &session_id);

    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, &sessions_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => vec![],
    };
    let (user_agent, ip) = request_client_metadata(&headers);

    sessions.push(UserSession {
        id: session_id,
        created_at: chrono::Utc::now().timestamp(),
        expires_at: expiry,
        ip,
        user_agent,
        name: None,
    });
    if sessions.len() > MAX_SESSIONS_PER_ACCOUNT {
        sessions.sort_by_key(|session| session.created_at);
        sessions.drain(..sessions.len() - MAX_SESSIONS_PER_ACCOUNT);
    }

    let sessions_json = serde_json::to_vec(&sessions)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    state
        .storage
        .put_object(
            &state.bucket,
            &sessions_key,
            sessions_json,
            Some("application/json"),
        )
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;

    let pfp_enc = fetch_user_pfp_enc(&state, &username).await;
    let role = account_role(&state, &username)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "token": token,
        "username": username,
        "role": role.as_str(),
        "pfp_enc": pfp_enc,
        "pfp": pfp_enc
    })))
}

#[derive(serde::Serialize)]
pub struct PasskeyResponse {
    pub id: String,
    pub name: Option<String>,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct PasskeyMeta {
    pub name: String,
}

async fn get_user_passkeys(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid token".into()))?;

    let passkeys_key = format!("users/{}/passkeys.json", username);
    let passkeys: Vec<webauthn_rs::prelude::Passkey> = match state
        .storage
        .get_object_bytes(&state.bucket, &passkeys_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => vec![],
    };

    let meta_key = format!("users/{}/passkeys_meta.json", username);
    let meta_map: std::collections::HashMap<String, PasskeyMeta> = match state
        .storage
        .get_object_bytes(&state.bucket, &meta_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => std::collections::HashMap::new(),
    };

    let res: Vec<PasskeyResponse> = passkeys
        .into_iter()
        .map(|pk| {
            use base64::Engine;
            let id = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(pk.cred_id());
            let name = meta_map.get(&id).map(|m| m.name.clone());
            PasskeyResponse { id, name }
        })
        .collect();

    Ok(Json(res))
}

async fn delete_user_passkey(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid token".into()))?;

    let passkeys_key = format!("users/{}/passkeys.json", username);
    let mut passkeys: Vec<webauthn_rs::prelude::Passkey> = match state
        .storage
        .get_object_bytes(&state.bucket, &passkeys_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => vec![],
    };

    use base64::Engine;
    let original_len = passkeys.len();
    passkeys.retain(|pk| {
        let pk_id = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(pk.cred_id());
        pk_id != id
    });
    if passkeys.len() == original_len {
        return Err((StatusCode::NOT_FOUND, "Passkey not found".to_string()));
    }

    let passkeys_json = serde_json::to_vec(&passkeys)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .storage
        .put_object(
            &state.bucket,
            &passkeys_key,
            passkeys_json,
            Some("application/json"),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = state
        .storage
        .delete_object(&state.bucket, &format!("passkey_index/{}", id))
        .await;

    let meta_key = format!("users/{}/passkeys_meta.json", username);
    if let Ok(bytes) = state
        .storage
        .get_object_bytes(&state.bucket, &meta_key)
        .await
    {
        if let Ok(mut meta_map) =
            serde_json::from_slice::<std::collections::HashMap<String, PasskeyMeta>>(&bytes)
        {
            meta_map.remove(&id);
            if let Ok(meta_json) = serde_json::to_vec(&meta_map) {
                let _ = state
                    .storage
                    .put_object(
                        &state.bucket,
                        &meta_key,
                        meta_json,
                        Some("application/json"),
                    )
                    .await;
            }
        }
    }

    Ok(Json(serde_json::json!({"success": true})))
}

#[derive(serde::Deserialize)]
pub struct RenamePasskeyPayload {
    pub name: String,
}

async fn rename_user_passkey(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<RenamePasskeyPayload>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid token".into()))?;

    let name = payload.name.trim().chars().take(64).collect::<String>();
    if name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Passkey name cannot be empty".to_string(),
        ));
    }
    let passkeys_key = format!("users/{}/passkeys.json", username);
    let passkeys: Vec<webauthn_rs::prelude::Passkey> = state
        .storage
        .get_object_bytes(&state.bucket, &passkeys_key)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    if !passkeys
        .iter()
        .any(|passkey| base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(passkey.cred_id()) == id)
    {
        return Err((StatusCode::NOT_FOUND, "Passkey not found".to_string()));
    }

    let meta_key = format!("users/{}/passkeys_meta.json", username);
    let mut meta_map: std::collections::HashMap<String, PasskeyMeta> = match state
        .storage
        .get_object_bytes(&state.bucket, &meta_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => std::collections::HashMap::new(),
    };

    meta_map.insert(id, PasskeyMeta { name });

    let meta_json = serde_json::to_vec(&meta_map)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .storage
        .put_object(
            &state.bucket,
            &meta_key,
            meta_json,
            Some("application/json"),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({"success": true})))
}

async fn api_not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "API endpoint not found")
}

// Serve the embedded SPA without caching HTML across binary upgrades.
async fn serve_index(State(state): State<AppState>) -> impl IntoResponse {
    let share_expiry_days = state.share_expiry_secs / (24 * 60 * 60);
    let html = include_str!("index.html")
        .replace(
            "__DILLSHARE_SHARE_EXPIRY_DAYS__",
            &share_expiry_days.to_string(),
        )
        .replace(
            "__DILLSHARE_MAX_SHARE_BYTES__",
            &state.max_share_bytes.to_string(),
        );
    (
        [
            (axum::http::header::CACHE_CONTROL, "no-cache"),
            (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (axum::http::header::REFERRER_POLICY, "no-referrer"),
            (axum::http::header::X_FRAME_OPTIONS, "DENY"),
        ],
        Html(html),
    )
}

// Serve the streaming-preview service worker. The browser requires this to be
// served from the same origin with an explicit JavaScript content type and a
// scope that allows it to control the SPA routes (e.g. /share/<uuid>).
async fn serve_service_worker() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript; charset=utf-8")
        .header(axum::http::header::CACHE_CONTROL, "no-cache")
        .header("service-worker-allowed", "/")
        .body(Body::from(include_str!("sw.js")))
        .unwrap()
}

// --- Embedded vendored frontend assets ---
//
// Every asset is embedded via include_str!/include_bytes! so the compiled
// binary is completely self-contained and runs offline without reaching out to
// any CDN. Long cache (1y immutable) since the bytes never change for a given
// binary build.

fn text_response(bytes: &'static str, content_type: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            axum::http::header::CACHE_CONTROL,
            "public, max-age=31536000, immutable",
        )
        .header(CONTENT_TYPE, content_type)
        .body(Body::from(bytes))
        .unwrap()
}

async fn serve_asset_streamsaver() -> impl IntoResponse {
    text_response(
        include_str!("vendor/streamsaver.min.js"),
        "application/javascript; charset=utf-8",
    )
}

async fn serve_asset_streamsaver_sw() -> impl IntoResponse {
    text_response(
        include_str!("vendor/streamsaver_sw.js"),
        "application/javascript; charset=utf-8",
    )
}

async fn serve_asset_streamsaver_mitm_html() -> impl IntoResponse {
    text_response(include_str!("vendor/mitm.html"), "text/html; charset=utf-8")
}

async fn serve_asset_jszip() -> impl IntoResponse {
    text_response(
        include_str!("vendor/jszip.min.js"),
        "application/javascript; charset=utf-8",
    )
}

async fn serve_asset_fflate() -> impl IntoResponse {
    text_response(
        include_str!("vendor/fflate.umd.js"),
        "application/javascript; charset=utf-8",
    )
}

async fn serve_asset_fonts_inline_css() -> impl IntoResponse {
    text_response(
        include_str!("vendor/fonts_inline.css"),
        "text/css; charset=utf-8",
    )
}

async fn serve_asset_marked() -> impl IntoResponse {
    text_response(
        include_str!("vendor/marked.min.js"),
        "application/javascript; charset=utf-8",
    )
}

const DIRECT_PUT_MAX_BYTES: i64 = 16 * 1024 * 1024;
const S3_PART_MAX_BYTES: i64 = 5 * 1024 * 1024 * 1024;
const ENCRYPTION_CHUNK_BYTES: i64 = 4 * 1024 * 1024;
const ENCRYPTION_OVERHEAD_BYTES: i64 = 28;
const MAX_FILES_PER_SHARE: usize = 1_000;
const METADATA_MAX_BYTES: i64 = 8 * 1024 * 1024;
const THUMBNAIL_MAX_BYTES: i64 = 2 * 1024 * 1024;
// Hex encoding doubles request size; keep this below the 16 MiB JSON body cap.
const USER_DATA_MAX_BYTES: usize = 7 * 1024 * 1024;
const MAX_SESSIONS_PER_ACCOUNT: usize = 100;
const MAX_PASSKEYS_PER_ACCOUNT: usize = 20;

fn is_valid_username(username: &str) -> bool {
    (3..=30).contains(&username.len())
        && username
            .chars()
            .all(|character| character.is_alphanumeric() || matches!(character, '-' | '_'))
}

fn is_valid_auth_key(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decode_hex(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, (StatusCode, String)> {
    if !value.len().is_multiple_of(2) || value.len() / 2 > maximum_bytes {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid or oversized encrypted payload".to_string(),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "Invalid encrypted payload hex encoding".to_string(),
                )
            })?;
            u8::from_str_radix(pair, 16).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "Invalid encrypted payload hex encoding".to_string(),
                )
            })
        })
        .collect()
}

fn request_client_metadata(headers: &axum::http::HeaderMap) -> (String, String) {
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("Unknown")
        .chars()
        .take(512)
        .collect();
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or("Unknown")
        .trim()
        .chars()
        .take(64)
        .collect();
    (user_agent, ip)
}

fn encrypted_file_size(plaintext_size: i64) -> Option<i64> {
    if plaintext_size < 0 {
        return None;
    }
    let chunks = if plaintext_size == 0 {
        1
    } else {
        plaintext_size.checked_add(ENCRYPTION_CHUNK_BYTES - 1)? / ENCRYPTION_CHUNK_BYTES
    };
    plaintext_size.checked_add(chunks.checked_mul(ENCRYPTION_OVERHEAD_BYTES)?)
}

fn multipart_part_sizes(plaintext_size: i64) -> Option<Vec<i64>> {
    let total_chunks = if plaintext_size == 0 {
        1usize
    } else {
        usize::try_from(
            plaintext_size.checked_add(ENCRYPTION_CHUNK_BYTES - 1)? / ENCRYPTION_CHUNK_BYTES,
        )
        .ok()?
    };
    let mut chunks_per_part = if plaintext_size >= 256 * 1024 * 1024 {
        8usize
    } else if plaintext_size >= 64 * 1024 * 1024 {
        4usize
    } else {
        2usize
    };
    chunks_per_part = chunks_per_part.max(total_chunks.div_ceil(9_000));

    let mut sizes = Vec::with_capacity(total_chunks.div_ceil(chunks_per_part));
    for start_chunk in (0..total_chunks).step_by(chunks_per_part) {
        let end_chunk = (start_chunk + chunks_per_part).min(total_chunks);
        let mut part_size = 0i64;
        for chunk in start_chunk..end_chunk {
            let start = i64::try_from(chunk)
                .ok()?
                .checked_mul(ENCRYPTION_CHUNK_BYTES)?;
            let plaintext_chunk = plaintext_size
                .saturating_sub(start)
                .clamp(0, ENCRYPTION_CHUNK_BYTES);
            part_size = part_size
                .checked_add(plaintext_chunk)?
                .checked_add(ENCRYPTION_OVERHEAD_BYTES)?;
        }
        if part_size <= 0 || part_size > S3_PART_MAX_BYTES {
            return None;
        }
        sizes.push(part_size);
    }
    Some(sizes)
}

fn parse_canonical_file_id(value: &str) -> Option<usize> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let id = value.parse::<usize>().ok()?;
    (id.to_string() == value).then_some(id)
}

fn payload_file_id(name: &str) -> Option<usize> {
    let id = name.strip_prefix("file_")?.strip_suffix(".enc")?;
    parse_canonical_file_id(id)
}

fn thumbnail_file_id(name: &str) -> Option<usize> {
    let id = name.strip_prefix("file_")?.strip_suffix(".thumb.enc")?;
    parse_canonical_file_id(id)
}

/// Only names generated by the client are allowed to become share object keys.
fn is_valid_upload_filename(name: &str) -> bool {
    name == "metadata.enc" || payload_file_id(name).is_some() || thumbnail_file_id(name).is_some()
}

fn is_valid_sha256_checksum(value: &str) -> bool {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map(|bytes| bytes.len() == 32)
        .unwrap_or(false)
}

fn is_canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

fn validate_upload_uuid(value: &str) -> Result<(), (StatusCode, String)> {
    if !is_canonical_uuid(value) {
        return Err((StatusCode::BAD_REQUEST, "Invalid upload ID".to_string()));
    }
    Ok(())
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ActiveUploadMarker {
    owner: String,
    created_at: i64,
    file_sizes: Vec<i64>,
    status: String,
}

async fn write_active_upload_marker(
    state: &AppState,
    uuid: &str,
    marker: &ActiveUploadMarker,
) -> Result<(), (StatusCode, String)> {
    let bytes = serde_json::to_vec(marker)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .storage
        .put_object(
            &state.bucket,
            &format!("uploads/{}/.active", uuid),
            bytes,
            Some("application/json"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update upload session: {}", e),
            )
        })
}

async fn authorize_upload_marker(
    state: &AppState,
    uuid: &str,
    username: &str,
    allowed_claimed_status: Option<&str>,
) -> Result<ActiveUploadMarker, (StatusCode, String)> {
    validate_upload_uuid(uuid)?;

    let owner_key = format!("uploads/{}/owner.txt", uuid);
    if state
        .storage
        .head_object_info(&state.bucket, &owner_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .is_some()
    {
        return Err((
            StatusCode::CONFLICT,
            "Upload session is already finalized".to_string(),
        ));
    }

    let active_key = format!("uploads/{}/.active", uuid);
    let bytes = state
        .storage
        .get_object_bytes(&state.bucket, &active_key)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                "Upload session not found".to_string(),
            )
        })?;
    let marker: ActiveUploadMarker = serde_json::from_slice(&bytes).map_err(|_| {
        (
            StatusCode::CONFLICT,
            "Upload session is invalid; start a new upload".to_string(),
        )
    })?;
    if marker.owner != username {
        return Err((
            StatusCode::FORBIDDEN,
            "Upload session belongs to another user".to_string(),
        ));
    }
    if marker.status != "active" && allowed_claimed_status != Some(marker.status.as_str()) {
        return Err((
            StatusCode::CONFLICT,
            "Upload session is being finalized or aborted".to_string(),
        ));
    }
    if chrono::Utc::now()
        .timestamp()
        .saturating_sub(marker.created_at)
        > state.upload_session_max_secs
    {
        return Err((StatusCode::GONE, "Upload session has expired".to_string()));
    }
    Ok(marker)
}

async fn authorize_active_upload(
    state: &AppState,
    uuid: &str,
    username: &str,
) -> Result<ActiveUploadMarker, (StatusCode, String)> {
    authorize_upload_marker(state, uuid, username, None).await
}

async fn claim_active_upload(
    state: &AppState,
    uuid: &str,
    username: &str,
    claimed_status: &str,
) -> Result<ActiveUploadMarker, (StatusCode, String)> {
    validate_upload_uuid(uuid)?;
    let owner_key = format!("uploads/{}/owner.txt", uuid);
    if state
        .storage
        .head_object_info(&state.bucket, &owner_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .is_some()
    {
        return Err((
            StatusCode::CONFLICT,
            "Upload session is already finalized".to_string(),
        ));
    }

    let active_key = format!("uploads/{}/.active", uuid);
    let active_info = state
        .storage
        .head_object_info(&state.bucket, &active_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "Upload session not found".to_string(),
            )
        })?;
    let e_tag = active_info.e_tag.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Upload session has no S3 ETag".to_string(),
        )
    })?;
    let bytes = state
        .storage
        .get_object_bytes(&state.bucket, &active_key)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                "Upload session not found".to_string(),
            )
        })?;
    let mut marker: ActiveUploadMarker = serde_json::from_slice(&bytes).map_err(|_| {
        (
            StatusCode::CONFLICT,
            "Upload session is invalid; start a new upload".to_string(),
        )
    })?;
    if marker.owner != username {
        return Err((
            StatusCode::FORBIDDEN,
            "Upload session belongs to another user".to_string(),
        ));
    }
    if chrono::Utc::now()
        .timestamp()
        .saturating_sub(marker.created_at)
        > state.upload_session_max_secs
    {
        return Err((StatusCode::GONE, "Upload session has expired".to_string()));
    }
    if marker.status == claimed_status {
        return Ok(marker);
    }
    if marker.status != "active" {
        return Err((
            StatusCode::CONFLICT,
            "Upload session has another operation in progress".to_string(),
        ));
    }

    marker.status = claimed_status.to_string();
    let claimed_bytes = serde_json::to_vec(&marker)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let claimed = state
        .storage
        .put_object_if_match(
            &state.bucket,
            &active_key,
            claimed_bytes,
            Some("application/json"),
            &e_tag,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if !claimed {
        return Err((
            StatusCode::CONFLICT,
            "Upload session changed concurrently; retry".to_string(),
        ));
    }
    Ok(marker)
}

#[derive(serde::Deserialize)]
struct UploadInitReq {
    file_sizes: Vec<i64>,
}

async fn upload_init(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<UploadInitReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    if !state.storage.supports_presigning() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Direct file transfers require an S3 bucket".to_string(),
        ));
    }
    if payload.file_sizes.is_empty() || payload.file_sizes.len() > MAX_FILES_PER_SHARE {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "A share must contain between 1 and {} files",
                MAX_FILES_PER_SHARE
            ),
        ));
    }
    let mut expected_payload_bytes = 0i64;
    for size in &payload.file_sizes {
        let encrypted_size = encrypted_file_size(*size)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid file size".to_string()))?;
        expected_payload_bytes = expected_payload_bytes
            .checked_add(encrypted_size)
            .ok_or_else(|| {
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Share is too large".to_string(),
                )
            })?;
    }
    if expected_payload_bytes > state.max_share_bytes {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "Share exceeds the configured storage limit".to_string(),
        ));
    }

    let uuid = uuid::Uuid::new_v4().to_string();
    let marker = ActiveUploadMarker {
        owner: username,
        created_at: chrono::Utc::now().timestamp(),
        file_sizes: payload.file_sizes,
        status: "active".to_string(),
    };
    write_active_upload_marker(&state, &uuid, &marker).await?;

    Ok(axum::Json(serde_json::json!({
        "uuid": uuid,
        "upload_mode": "direct"
    })))
}

async fn upload_ping(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;
    authorize_active_upload(&state, &uuid, &username).await?;

    Ok(axum::Json(serde_json::json!({ "status": "ok" })))
}

#[derive(serde::Deserialize)]
struct UploadPresignReq {
    file_name: String,
    content_length: i64,
    checksum_sha256: String,
}

async fn upload_presign(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<UploadPresignReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;
    let marker = authorize_active_upload(&state, &uuid, &username).await?;

    if !is_valid_upload_filename(&payload.file_name)
        || !is_valid_sha256_checksum(&payload.checksum_sha256)
    {
        return Err((StatusCode::BAD_REQUEST, "Invalid file name".to_string()));
    }
    let maximum_size = if payload.file_name == "metadata.enc" {
        METADATA_MAX_BYTES
    } else if let Some(id) = thumbnail_file_id(&payload.file_name) {
        if id >= marker.file_sizes.len() {
            return Err((StatusCode::BAD_REQUEST, "Invalid file ID".to_string()));
        }
        THUMBNAIL_MAX_BYTES
    } else if let Some(id) = payload_file_id(&payload.file_name) {
        let plaintext_size = marker
            .file_sizes
            .get(id)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid file ID".to_string()))?;
        let expected_size = encrypted_file_size(*plaintext_size)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid file size".to_string()))?;
        if payload.content_length != expected_size {
            return Err((
                StatusCode::BAD_REQUEST,
                "Encrypted file size does not match the upload declaration".to_string(),
            ));
        }
        DIRECT_PUT_MAX_BYTES
    } else {
        return Err((StatusCode::BAD_REQUEST, "Invalid file name".to_string()));
    };
    if !(1..=maximum_size).contains(&payload.content_length) {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Direct PUT size must be between 1 and {} bytes",
                maximum_size
            ),
        ));
    }

    let key = format!("uploads/{}/{}", uuid, payload.file_name);
    if let Some(existing) = state
        .storage
        .head_object_info(&state.bucket, &key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    {
        if existing.size == payload.content_length {
            return Ok(axum::Json(serde_json::json!({
                "already_uploaded": true
            })));
        }
        return Err((
            StatusCode::CONFLICT,
            "An object with this name already exists with a different size".to_string(),
        ));
    }

    let request = state
        .storage
        .presign_put_object(
            &state.bucket,
            &key,
            payload.content_length,
            &payload.checksum_sha256,
            state.presign_ttl,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(axum::Json(serde_json::json!({
        "already_uploaded": false,
        "method": request.method,
        "url": request.url,
        "headers": request.headers,
        "expires_in": state.presign_ttl.as_secs()
    })))
}

#[derive(serde::Deserialize)]
struct UploadFinishReq {
    files_count: usize,
    total_size: i64,
}

const FINALIZED_MANIFEST_NAME: &str = ".manifest.json";

#[derive(serde::Deserialize, serde::Serialize)]
struct FinalizedShareManifest {
    version: u8,
    owner: String,
    created_at: i64,
    expires_at: i64,
    plaintext_size: i64,
    stored_size: i64,
    files: std::collections::BTreeMap<String, i64>,
}

async fn load_finalized_manifest(
    state: &AppState,
    uuid: &str,
) -> Result<Option<FinalizedShareManifest>, (StatusCode, String)> {
    let key = format!("uploads/{}/{}", uuid, FINALIZED_MANIFEST_NAME);
    if state
        .storage
        .head_object_info(&state.bucket, &key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .is_none()
    {
        return Ok(None);
    }
    let bytes = state
        .storage
        .get_object_bytes(&state.bucket, &key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let manifest = serde_json::from_slice(&bytes).map_err(|_| {
        (
            StatusCode::CONFLICT,
            "Share manifest is invalid".to_string(),
        )
    })?;
    Ok(Some(manifest))
}

async fn prune_share_to_manifest(
    storage: &storage::Storage,
    bucket: &str,
    uuid: &str,
) -> Result<(), String> {
    let manifest_key = format!("uploads/{}/{}", uuid, FINALIZED_MANIFEST_NAME);
    let bytes = storage.get_object_bytes(bucket, &manifest_key).await?;
    let manifest: FinalizedShareManifest =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let prefix = format!("uploads/{}/", uuid);
    let mut allowed = std::collections::HashSet::new();
    allowed.insert(format!("{}owner.txt", prefix));
    allowed.insert(manifest_key);
    for file_name in manifest.files.keys() {
        allowed.insert(format!("{}{}", prefix, file_name));
    }

    let objects = storage.list_objects(bucket, Some(&prefix), None).await?;
    let extra_keys: Vec<String> = objects
        .into_iter()
        .map(|object| object.key)
        .filter(|key| !allowed.contains(key))
        .collect();
    storage.delete_objects_batch(bucket, &extra_keys).await?;

    if let Ok(multipart_uploads) = storage.list_multipart_uploads(bucket).await {
        for upload in multipart_uploads {
            if upload.key.starts_with(&prefix) {
                let _ = storage
                    .abort_multipart_upload(bucket, &upload.key, &upload.upload_id)
                    .await;
            }
        }
    }
    Ok(())
}

async fn upsert_public_share(
    state: &AppState,
    username: &str,
    share: serde_json::Value,
) -> Result<(), (StatusCode, String)> {
    let key = format!("users/{}/public_shares.json", username);
    let uuid = share
        .get("uuid")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Public share record has no UUID".to_string(),
            )
        })?
        .to_string();

    for _ in 0..8 {
        match state
            .storage
            .get_object_bytes_with_etag(&state.bucket, &key)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        {
            Some((bytes, e_tag)) => {
                let mut shares =
                    serde_json::from_slice::<Vec<serde_json::Value>>(&bytes).unwrap_or_default();
                shares.retain(|entry| {
                    entry.get("uuid").and_then(|value| value.as_str()) != Some(uuid.as_str())
                });
                shares.push(share.clone());
                let updated = serde_json::to_vec(&shares)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                if state
                    .storage
                    .put_object_if_match(
                        &state.bucket,
                        &key,
                        updated,
                        Some("application/json"),
                        &e_tag,
                    )
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
                {
                    return Ok(());
                }
            }
            None => {
                let initial = serde_json::to_vec(&vec![share.clone()])
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                if state
                    .storage
                    .put_object_if_absent(&state.bucket, &key, initial, Some("application/json"))
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
                {
                    return Ok(());
                }
            }
        }
        tokio::task::yield_now().await;
    }

    Err((
        StatusCode::CONFLICT,
        "Share index changed too many times; retry finalization".to_string(),
    ))
}

async fn upload_finish(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<UploadFinishReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    validate_upload_uuid(&uuid)?;
    let owner_key = format!("uploads/{}/owner.txt", uuid);
    if let Ok(owner_bytes) = state
        .storage
        .get_object_bytes(&state.bucket, &owner_key)
        .await
    {
        let owner = String::from_utf8(owner_bytes).unwrap_or_default();
        if owner.trim() != username {
            return Err((
                StatusCode::FORBIDDEN,
                "Share belongs to another user".to_string(),
            ));
        }
        let manifest_bytes = state
            .storage
            .get_object_bytes(
                &state.bucket,
                &format!("uploads/{}/{}", uuid, FINALIZED_MANIFEST_NAME),
            )
            .await
            .map_err(|_| {
                (
                    StatusCode::CONFLICT,
                    "Finalized share manifest is missing".to_string(),
                )
            })?;
        let manifest: FinalizedShareManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|_| {
                (
                    StatusCode::CONFLICT,
                    "Finalized share manifest is invalid".to_string(),
                )
            })?;
        let files_count = manifest
            .files
            .keys()
            .filter(|name| payload_file_id(name).is_some())
            .count();
        if manifest.owner != username
            || manifest.plaintext_size != payload.total_size
            || files_count != payload.files_count
        {
            return Err((
                StatusCode::CONFLICT,
                "Finalized share does not match this request".to_string(),
            ));
        }
        let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp(manifest.created_at, 0)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339();
        upsert_public_share(
            &state,
            &username,
            serde_json::json!({
                "uuid": uuid,
                "files_count": files_count,
                "total_size": manifest.plaintext_size,
                "stored_size": manifest.stored_size,
                "created_at": created_at
            }),
        )
        .await?;
        return Ok(axum::Json(serde_json::json!({
            "uuid": uuid,
            "files": manifest.files.keys().collect::<Vec<_>>()
        })));
    }
    let marker = authorize_upload_marker(&state, &uuid, &username, Some("finishing")).await?;

    let declared_total_size = marker
        .file_sizes
        .iter()
        .try_fold(0i64, |total, size| total.checked_add(*size));
    if payload.files_count != marker.file_sizes.len()
        || declared_total_size != Some(payload.total_size)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Finalized share does not match the upload declaration".to_string(),
        ));
    }

    let prefix = format!("uploads/{}/", uuid);
    let mut uploaded_files = Vec::new();
    let mut manifest_files = std::collections::BTreeMap::new();
    let mut control_keys = Vec::new();
    let mut stored_size = 0i64;
    let mut payload_ids = std::collections::HashSet::new();
    let mut has_metadata = false;

    let objects = state
        .storage
        .list_objects(&state.bucket, Some(&prefix), None)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    for object in objects {
        let relative = object
            .key
            .strip_prefix(&prefix)
            .unwrap_or(&object.key)
            .to_string();
        if relative == ".active" || relative == FINALIZED_MANIFEST_NAME {
            continue;
        }
        if relative.starts_with(".multipart-") && relative.ends_with(".json") {
            control_keys.push(object.key);
            continue;
        }
        if relative == "metadata.enc" {
            has_metadata = (1..=METADATA_MAX_BYTES).contains(&object.size);
            if !has_metadata {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Encrypted metadata exceeds the allowed size".to_string(),
                ));
            }
        } else if let Some(id) = payload_file_id(&relative) {
            let expected_size = marker
                .file_sizes
                .get(id)
                .and_then(|size| encrypted_file_size(*size));
            if expected_size != Some(object.size) || !payload_ids.insert(id) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Uploaded file set does not match the finalized share".to_string(),
                ));
            }
        } else if let Some(id) = thumbnail_file_id(&relative) {
            if id >= marker.file_sizes.len() || !(1..=THUMBNAIL_MAX_BYTES).contains(&object.size) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Uploaded thumbnail set does not match the finalized share".to_string(),
                ));
            }
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                "Upload contains an unexpected object".to_string(),
            ));
        }
        stored_size = stored_size.checked_add(object.size).ok_or_else(|| {
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Share is too large".to_string(),
            )
        })?;
        manifest_files.insert(relative.clone(), object.size);
        uploaded_files.push(relative);
    }

    if !has_metadata || payload_ids.len() != payload.files_count {
        return Err((StatusCode::BAD_REQUEST, "Upload is incomplete".to_string()));
    }
    for id in 0..payload.files_count {
        if !payload_ids.contains(&id) {
            return Err((
                StatusCode::BAD_REQUEST,
                "Upload file IDs must be contiguous".to_string(),
            ));
        }
    }

    if stored_size > state.max_share_bytes {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "Share exceeds the configured storage limit".to_string(),
        ));
    }

    let claimed_marker = claim_active_upload(&state, &uuid, &username, "finishing").await?;
    if claimed_marker.created_at != marker.created_at
        || claimed_marker.file_sizes != marker.file_sizes
    {
        return Err((
            StatusCode::CONFLICT,
            "Upload declaration changed during finalization".to_string(),
        ));
    }

    let finished_at = chrono::Utc::now().timestamp();
    let manifest = FinalizedShareManifest {
        version: 1,
        owner: username.clone(),
        created_at: marker.created_at,
        expires_at: finished_at.saturating_add(state.share_expiry_secs),
        plaintext_size: payload.total_size,
        stored_size,
        files: manifest_files,
    };
    let manifest_bytes = serde_json::to_vec(&manifest)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .storage
        .put_object(
            &state.bucket,
            &format!("{}{}", prefix, FINALIZED_MANIFEST_NAME),
            manifest_bytes,
            Some("application/json"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save finalized share manifest: {}", e),
            )
        })?;

    let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp(marker.created_at, 0)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339();
    upsert_public_share(
        &state,
        &username,
        serde_json::json!({
            "uuid": uuid,
            "files_count": payload.files_count,
            "total_size": payload.total_size,
            "stored_size": stored_size,
            "created_at": created_at
        }),
    )
    .await?;

    let owner_created = state
        .storage
        .put_object_if_absent(
            &state.bucket,
            &owner_key,
            username.as_bytes().to_vec(),
            Some("text/plain"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save owner: {}", e),
            )
        })?;
    if !owner_created {
        let existing_owner = state
            .storage
            .get_object_bytes(&state.bucket, &owner_key)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if String::from_utf8(existing_owner).unwrap_or_default().trim() != username {
            return Err((
                StatusCode::CONFLICT,
                "Share was finalized by another user".to_string(),
            ));
        }
    }

    let active_key = format!("uploads/{}/.active", uuid);
    if let Err(error) = state
        .storage
        .delete_object(&state.bucket, &active_key)
        .await
    {
        tracing::warn!(
            "Failed to remove finalized upload marker for {}: {}",
            uuid,
            error
        );
    }
    if let Err(error) = state
        .storage
        .delete_objects_batch(&state.bucket, &control_keys)
        .await
    {
        tracing::warn!(
            "Failed to remove multipart control records for {}: {}",
            uuid,
            error
        );
    }

    let cleanup_storage = state.storage.clone();
    let cleanup_bucket = state.bucket.clone();
    let cleanup_uuid = uuid.clone();
    let cleanup_delay = state.presign_ttl + std::time::Duration::from_secs(5);
    tokio::spawn(async move {
        tokio::time::sleep(cleanup_delay).await;
        if let Err(error) =
            prune_share_to_manifest(&cleanup_storage, &cleanup_bucket, &cleanup_uuid).await
        {
            tracing::warn!(
                "Failed to prune post-finalization objects for {}: {}",
                cleanup_uuid,
                error
            );
        }
    });

    uploaded_files.sort();

    Ok(axum::Json(serde_json::json!({
        "uuid": uuid,
        "files": uploaded_files
    })))
}

async fn upload_abort(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;
    claim_active_upload(&state, &uuid, &username, "aborting").await?;

    let prefix = format!("uploads/{}/", uuid);
    tracing::info!(
        "Aborting upload session {}; cleaning up S3 prefix '{}'",
        uuid,
        prefix
    );
    if let Ok(multipart_uploads) = state.storage.list_multipart_uploads(&state.bucket).await {
        for upload in multipart_uploads {
            if upload.key.starts_with(&prefix) {
                let _ = state
                    .storage
                    .abort_multipart_upload(&state.bucket, &upload.key, &upload.upload_id)
                    .await;
            }
        }
    }
    delete_s3_prefix(&state.storage, &state.bucket, &prefix).await?;

    let cleanup_storage = state.storage.clone();
    let cleanup_bucket = state.bucket.clone();
    let cleanup_prefix = prefix.clone();
    let cleanup_delay = state.presign_ttl + std::time::Duration::from_secs(5);
    tokio::spawn(async move {
        tokio::time::sleep(cleanup_delay).await;
        if let Ok(multipart_uploads) = cleanup_storage
            .list_multipart_uploads(&cleanup_bucket)
            .await
        {
            for upload in multipart_uploads {
                if upload.key.starts_with(&cleanup_prefix) {
                    let _ = cleanup_storage
                        .abort_multipart_upload(&cleanup_bucket, &upload.key, &upload.upload_id)
                        .await;
                }
            }
        }
        let _ = delete_s3_prefix(&cleanup_storage, &cleanup_bucket, &cleanup_prefix).await;
    });

    Ok(axum::Json(serde_json::json!({ "status": "aborted" })))
}

#[derive(serde::Deserialize)]
struct MultipartInitReq {
    file_name: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct MultipartUploadRecord {
    upload_id: String,
    file_name: String,
    part_sizes: Vec<i64>,
    #[serde(default)]
    completed: bool,
}

fn multipart_record_key(uuid: &str, file_id: usize) -> String {
    format!("uploads/{}/.multipart-{}.json", uuid, file_id)
}

async fn upload_multipart_init(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<MultipartInitReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;
    let marker = authorize_active_upload(&state, &uuid, &username).await?;

    let file_id = payload_file_id(&payload.file_name).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Multipart uploads are only allowed for encrypted file payloads".to_string(),
        )
    })?;
    let plaintext_size = marker
        .file_sizes
        .get(file_id)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid file ID".to_string()))?;
    let part_sizes = multipart_part_sizes(*plaintext_size).ok_or_else(|| {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "File cannot be represented as a valid S3 multipart upload".to_string(),
        )
    })?;
    if part_sizes.len() > 10_000 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "File requires too many multipart parts".to_string(),
        ));
    }

    let key = format!("uploads/{}/{}", uuid, payload.file_name);
    let record_key = multipart_record_key(&uuid, file_id);
    if let Ok(bytes) = state
        .storage
        .get_object_bytes(&state.bucket, &record_key)
        .await
    {
        let record: MultipartUploadRecord = serde_json::from_slice(&bytes).map_err(|_| {
            (
                StatusCode::CONFLICT,
                "Multipart upload state is invalid; restart the share".to_string(),
            )
        })?;
        if record.file_name == payload.file_name && record.part_sizes == part_sizes {
            return Ok(axum::Json(serde_json::json!({
                "upload_id": record.upload_id
            })));
        }
        return Err((
            StatusCode::CONFLICT,
            "A different multipart upload already exists for this file".to_string(),
        ));
    }
    if state
        .storage
        .head_object_info(&state.bucket, &key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .is_some()
    {
        return Err((
            StatusCode::CONFLICT,
            "File payload already exists".to_string(),
        ));
    }

    let upload_id = state
        .storage
        .create_multipart_upload(&state.bucket, &key, Some("application/octet-stream"))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create S3 multipart upload: {:?}", e),
            )
        })?;

    let record = MultipartUploadRecord {
        upload_id: upload_id.clone(),
        file_name: payload.file_name,
        part_sizes,
        completed: false,
    };
    let record_bytes = serde_json::to_vec(&record)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let record_created = match state
        .storage
        .put_object_if_absent(
            &state.bucket,
            &record_key,
            record_bytes,
            Some("application/json"),
        )
        .await
    {
        Ok(created) => created,
        Err(error) => {
            let _ = state
                .storage
                .abort_multipart_upload(&state.bucket, &key, &upload_id)
                .await;
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save multipart upload state: {}", error),
            ));
        }
    };
    if !record_created {
        let _ = state
            .storage
            .abort_multipart_upload(&state.bucket, &key, &upload_id)
            .await;
        let bytes = state
            .storage
            .get_object_bytes(&state.bucket, &record_key)
            .await
            .map_err(|_| {
                (
                    StatusCode::CONFLICT,
                    "Multipart upload was initialized concurrently; retry".to_string(),
                )
            })?;
        let existing: MultipartUploadRecord = serde_json::from_slice(&bytes).map_err(|_| {
            (
                StatusCode::CONFLICT,
                "Multipart upload state is invalid; restart the share".to_string(),
            )
        })?;
        if existing.file_name == record.file_name && existing.part_sizes == record.part_sizes {
            return Ok(axum::Json(serde_json::json!({
                "upload_id": existing.upload_id
            })));
        }
        return Err((
            StatusCode::CONFLICT,
            "A different multipart upload already exists for this file".to_string(),
        ));
    }

    Ok(axum::Json(serde_json::json!({ "upload_id": upload_id })))
}

#[derive(serde::Deserialize)]
struct MultipartPartUrlReq {
    upload_id: String,
    part_number: i32,
    file_name: String,
    content_length: i64,
    checksum_sha256: String,
}

async fn upload_multipart_part_url(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<MultipartPartUrlReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;
    authorize_active_upload(&state, &uuid, &username).await?;

    let file_id = payload_file_id(&payload.file_name).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Multipart uploads are only allowed for encrypted file payloads".to_string(),
        )
    })?;
    if !(1..=10_000).contains(&payload.part_number) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Part number must be between 1 and 10000".to_string(),
        ));
    }
    if !(1..=S3_PART_MAX_BYTES).contains(&payload.content_length)
        || !is_valid_sha256_checksum(&payload.checksum_sha256)
    {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "Multipart part size is outside S3 limits".to_string(),
        ));
    }
    if payload.upload_id.is_empty()
        || payload.upload_id.len() > 1024
        || !payload
            .upload_id
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
    {
        return Err((StatusCode::BAD_REQUEST, "Invalid upload ID".to_string()));
    }

    let key = format!("uploads/{}/{}", uuid, payload.file_name);
    let record_bytes = state
        .storage
        .get_object_bytes(&state.bucket, &multipart_record_key(&uuid, file_id))
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                "Multipart upload session not found".to_string(),
            )
        })?;
    let record: MultipartUploadRecord = serde_json::from_slice(&record_bytes).map_err(|_| {
        (
            StatusCode::CONFLICT,
            "Multipart upload state is invalid; restart the share".to_string(),
        )
    })?;
    let expected_size = record
        .part_sizes
        .get((payload.part_number - 1) as usize)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid part number".to_string()))?;
    if record.upload_id != payload.upload_id
        || record.file_name != payload.file_name
        || *expected_size != payload.content_length
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Multipart part does not match the declared upload".to_string(),
        ));
    }
    if record.completed {
        return Err((
            StatusCode::CONFLICT,
            "Multipart upload is already complete".to_string(),
        ));
    }

    let request = state
        .storage
        .presign_upload_part(
            storage::UploadPartRequest {
                bucket: &state.bucket,
                key: &key,
                upload_id: &payload.upload_id,
                part_number: payload.part_number,
                content_length: payload.content_length,
                checksum_sha256: &payload.checksum_sha256,
            },
            state.presign_ttl,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to sign multipart upload: {}", e),
            )
        })?;

    Ok(axum::Json(serde_json::json!({
        "method": request.method,
        "url": request.url,
        "headers": request.headers,
        "expires_in": state.presign_ttl.as_secs()
    })))
}

#[derive(serde::Deserialize)]
struct CompletedPartReq {
    part_number: i32,
    e_tag: String,
    checksum_sha256: String,
}

#[derive(serde::Deserialize)]
struct MultipartCompleteReq {
    upload_id: String,
    file_name: String,
    parts: Vec<CompletedPartReq>,
}

async fn upload_multipart_complete(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<MultipartCompleteReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;
    authorize_active_upload(&state, &uuid, &username).await?;

    let file_id = payload_file_id(&payload.file_name).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Multipart uploads are only allowed for encrypted file payloads".to_string(),
        )
    })?;
    if payload.upload_id.is_empty() || payload.upload_id.len() > 1024 {
        return Err((StatusCode::BAD_REQUEST, "Invalid upload ID".to_string()));
    }
    if payload.parts.is_empty() || payload.parts.len() > 10_000 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Multipart upload must contain between 1 and 10000 parts".to_string(),
        ));
    }
    let record_key = multipart_record_key(&uuid, file_id);
    let record_bytes = state
        .storage
        .get_object_bytes(&state.bucket, &record_key)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                "Multipart upload session not found".to_string(),
            )
        })?;
    let mut record: MultipartUploadRecord =
        serde_json::from_slice(&record_bytes).map_err(|_| {
            (
                StatusCode::CONFLICT,
                "Multipart upload state is invalid; restart the share".to_string(),
            )
        })?;
    if record.upload_id != payload.upload_id
        || record.file_name != payload.file_name
        || record.part_sizes.len() != payload.parts.len()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Multipart completion does not match the declared upload".to_string(),
        ));
    }
    let expected_object_size = record
        .part_sizes
        .iter()
        .try_fold(0i64, |total, size| total.checked_add(*size));
    if record.completed {
        let existing = state
            .storage
            .head_object_info(
                &state.bucket,
                &format!("uploads/{}/{}", uuid, payload.file_name),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if existing.as_ref().map(|object| object.size) == expected_object_size {
            return Ok(axum::Json(serde_json::json!({ "status": "ok" })));
        }
        return Err((
            StatusCode::CONFLICT,
            "Completed multipart object is missing or has the wrong size".to_string(),
        ));
    }
    for (index, part) in payload.parts.iter().enumerate() {
        if part.part_number != (index + 1) as i32 {
            return Err((
                StatusCode::BAD_REQUEST,
                "Multipart part numbers must be unique, ordered, and contiguous".to_string(),
            ));
        }
        if part.e_tag.is_empty()
            || part.e_tag.len() > 256
            || part.e_tag.chars().any(char::is_control)
            || !is_valid_sha256_checksum(&part.checksum_sha256)
        {
            return Err((
                StatusCode::BAD_REQUEST,
                "Invalid multipart ETag".to_string(),
            ));
        }
    }

    let key = format!("uploads/{}/{}", uuid, payload.file_name);

    if let Some(existing) = state
        .storage
        .head_object_info(&state.bucket, &key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    {
        if Some(existing.size) != expected_object_size {
            return Err((
                StatusCode::CONFLICT,
                "Existing multipart object has the wrong size".to_string(),
            ));
        }
        let _ = state
            .storage
            .abort_multipart_upload(&state.bucket, &key, &payload.upload_id)
            .await;
        record.completed = true;
        let completed_record = serde_json::to_vec(&record)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        state
            .storage
            .put_object(
                &state.bucket,
                &record_key,
                completed_record,
                Some("application/json"),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        return Ok(axum::Json(serde_json::json!({ "status": "ok" })));
    }

    let mut completed_parts = Vec::new();
    for p in payload.parts {
        let completed_part = crate::storage::CompletedPart {
            part_number: p.part_number,
            e_tag: p.e_tag,
            checksum_sha256: p.checksum_sha256,
        };
        completed_parts.push(completed_part);
    }

    state
        .storage
        .complete_multipart_upload(&state.bucket, &key, &payload.upload_id, completed_parts)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to complete S3 multipart upload: {:?}", e),
            )
        })?;

    record.completed = true;
    let completed_record = serde_json::to_vec(&record)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .storage
        .put_object(
            &state.bucket,
            &record_key,
            completed_record,
            Some("application/json"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save completed multipart state: {}", e),
            )
        })?;

    Ok(axum::Json(serde_json::json!({ "status": "ok" })))
}

// Get details of a single share UUID
async fn get_share(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    validate_upload_uuid(&uuid)?;
    let prefix = format!("uploads/{}/", uuid);
    let owner_key = format!("uploads/{}/owner.txt", uuid);
    let owner_info = state
        .storage
        .head_object_info(&state.bucket, &owner_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "Share not found or expired".to_string(),
            )
        })?;
    let now = chrono::Utc::now().timestamp();
    if now.saturating_sub(owner_info.last_modified_secs) > state.share_expiry_secs {
        return Err((
            StatusCode::NOT_FOUND,
            "Share not found or expired".to_string(),
        ));
    }

    #[derive(serde::Serialize)]
    struct ShareFile {
        name: String,
        size: i64,
    }

    #[derive(serde::Serialize)]
    struct ShareDetails {
        uuid: String,
        upload_time: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
        files: Vec<ShareFile>,
        owner: String,
        owner_pfp: Option<String>,
    }

    let mut files = Vec::new();
    let latest_upload_time =
        chrono::DateTime::<chrono::Utc>::from_timestamp(owner_info.last_modified_secs, 0)
            .unwrap_or_else(chrono::Utc::now);
    let mut has_objects = false;
    let manifest = load_finalized_manifest(&state, &uuid).await?;

    if let Some(manifest) = &manifest {
        if manifest.expires_at <= now {
            return Err((
                StatusCode::NOT_FOUND,
                "Share not found or expired".to_string(),
            ));
        }
        has_objects = manifest.files.contains_key("metadata.enc");
        for (file_name, size) in &manifest.files {
            if payload_file_id(file_name).is_some() {
                files.push(ShareFile {
                    name: file_name.clone(),
                    size: *size,
                });
            }
        }
    } else {
        // Read-only compatibility for shares finalized before manifests existed.
        let objects = state
            .storage
            .list_objects(&state.bucket, Some(&prefix), None)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

        for object in objects {
            let key = object.key;
            let size = object.size;
            let file_name = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
            if file_name == "owner.txt"
                || file_name == ".active"
                || file_name == FINALIZED_MANIFEST_NAME
                || file_name.starts_with(".multipart-")
            {
                continue;
            }
            has_objects = true;
            if file_name == "metadata.enc" || thumbnail_file_id(&file_name).is_some() {
                continue;
            }
            if payload_file_id(&file_name).is_some() {
                files.push(ShareFile {
                    name: file_name,
                    size,
                });
            }
        }
    }

    if !has_objects {
        return Err((
            StatusCode::NOT_FOUND,
            "Share not found or expired".to_string(),
        ));
    }

    let owner_res = state
        .storage
        .get_object_bytes(&state.bucket, &owner_key)
        .await;

    let owner = match owner_res {
        Ok(bytes) => String::from_utf8(bytes)
            .unwrap_or_default()
            .trim()
            .to_string(),
        Err(_) => String::new(),
    };
    if let Some(manifest) = &manifest {
        if manifest.owner != owner {
            return Err((
                StatusCode::CONFLICT,
                "Share ownership is invalid".to_string(),
            ));
        }
    }

    let owner_pfp = None;

    let expires_at = manifest
        .as_ref()
        .and_then(|manifest| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(manifest.expires_at, 0)
        })
        .unwrap_or_else(|| latest_upload_time + chrono::Duration::seconds(state.share_expiry_secs));

    Ok(axum::Json(ShareDetails {
        uuid,
        upload_time: latest_upload_time,
        expires_at,
        files,
        owner,
        owner_pfp,
    }))
}

async fn create_download_request(
    state: &AppState,
    uuid: &str,
    filename: &str,
) -> Result<(storage::PresignedRequest, u64), (StatusCode, String)> {
    if !state.storage.supports_presigning() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Direct file transfers require an S3 bucket".to_string(),
        ));
    }
    validate_upload_uuid(uuid)?;
    if !is_valid_upload_filename(filename) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid share file path".to_string(),
        ));
    }

    let owner_key = format!("uploads/{}/owner.txt", uuid);
    let owner_info = state
        .storage
        .head_object_info(&state.bucket, &owner_key)
        .await
        .map_err(|error| {
            tracing::error!("S3 HeadObject error for share owner: {}", error);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "Share not found or expired".to_string(),
            )
        })?;
    let now = chrono::Utc::now().timestamp();
    let owner_expires_at = owner_info
        .last_modified_secs
        .saturating_add(state.share_expiry_secs);
    if now >= owner_expires_at {
        return Err((
            StatusCode::NOT_FOUND,
            "Share not found or expired".to_string(),
        ));
    }

    let key = format!("uploads/{}/{}", uuid, filename);
    let mut expires_at = owner_expires_at;
    match load_finalized_manifest(state, uuid).await {
        Ok(Some(manifest)) => {
            expires_at = expires_at.min(manifest.expires_at);
            if now >= expires_at || !manifest.files.contains_key(filename) {
                return Err((StatusCode::NOT_FOUND, "File not found".to_string()));
            }
        }
        Ok(None) => {
            // Read-only compatibility for shares finalized before manifests existed.
            match state.storage.head_object_info(&state.bucket, &key).await {
                Ok(Some(_)) => {}
                Ok(None) => return Err((StatusCode::NOT_FOUND, "File not found".to_string())),
                Err(error) => {
                    tracing::error!("S3 HeadObject error for share file: {}", error);
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error".to_string(),
                    ));
                }
            }
        }
        Err(error) => return Err(error),
    }

    let remaining_secs = expires_at.saturating_sub(now) as u64;
    let presign_ttl =
        std::time::Duration::from_secs(state.presign_ttl.as_secs().min(remaining_secs).max(1));

    let request = state
        .storage
        .presign_get_object(&state.bucket, &key, presign_ttl)
        .await
        .map_err(|error| {
            tracing::error!("Failed to presign S3 download: {}", error);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
        })?;
    Ok((request, presign_ttl.as_secs()))
}

async fn get_download_url(
    State(state): State<AppState>,
    Path((uuid, filename)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (request, expires_in) = create_download_request(&state, &uuid, &filename).await?;
    Ok(axum::Json(serde_json::json!({
        "url": request.url,
        "expires_in": expires_in
    })))
}

// Range headers are retained by the 307, so file bytes never pass through this server.
async fn download_file(
    State(state): State<AppState>,
    method: axum::http::Method,
    Path((uuid, filename)): Path<(String, String)>,
) -> impl IntoResponse {
    if method != axum::http::Method::GET {
        return (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed").into_response();
    }
    let (request, _) = match create_download_request(&state, &uuid, &filename).await {
        Ok(result) => result,
        Err(error) => return error.into_response(),
    };

    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(axum::http::header::LOCATION, request.url)
        .header(
            axum::http::header::CACHE_CONTROL,
            "private, no-store, max-age=0",
        )
        .header("referrer-policy", "no-referrer")
        .header("x-content-type-options", "nosniff")
        .body(Body::empty())
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        })
}

// Delete an entire share from S3
// Delete share - requires ownership verification
async fn delete_share(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    validate_upload_uuid(&uuid)?;

    // Check ownership
    let owner_key = format!("uploads/{}/owner.txt", uuid);
    let owner_res = state
        .storage
        .get_object_bytes(&state.bucket, &owner_key)
        .await;

    let owner = match owner_res {
        Ok(bytes) => String::from_utf8(bytes)
            .unwrap_or_default()
            .trim()
            .to_string(),
        Err(_) => {
            return Err((StatusCode::NOT_FOUND, "Share not found".to_string()));
        }
    };

    if owner != username {
        return Err((
            StatusCode::FORBIDDEN,
            "You do not own this share".to_string(),
        ));
    }

    // Delete objects from S3
    delete_share_objects(&state.storage, &state.bucket, &uuid).await?;

    // Remove from owner's public shares index in S3
    remove_share_from_user_index(&state.storage, &state.bucket, &username, &uuid).await;

    Ok(axum::Json(serde_json::json!({ "status": "deleted" })))
}

async fn remove_share_from_user_index(
    storage: &storage::Storage,
    bucket: &str,
    username: &str,
    uuid: &str,
) {
    let user_key = format!("users/{}.json", username);
    if let Ok(bytes) = storage.get_object_bytes(bucket, &user_key).await {
        if let Ok(mut user_json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(obj) = user_json.as_object_mut() {
                if let Some(shares) = obj.get_mut("shares") {
                    if let Some(shares_array) = shares.as_array_mut() {
                        shares_array.retain(|v| v.as_str() != Some(uuid));
                        if let Ok(user_bytes) = serde_json::to_vec(&user_json) {
                            let _ = storage
                                .put_object(bucket, &user_key, user_bytes, Some("application/json"))
                                .await;
                        }
                    }
                }
            }
        }
    }

    if username.is_empty() {
        return;
    }
    let public_shares_key = format!("users/{}/public_shares.json", username);
    for _ in 0..8 {
        match storage
            .get_object_bytes_with_etag(bucket, &public_shares_key)
            .await
        {
            Ok(Some((bytes, e_tag))) => {
                if let Ok(mut shares) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
                    shares.retain(|s| s.get("uuid").and_then(|u| u.as_str()) != Some(uuid));
                    if let Ok(shares_bytes) = serde_json::to_vec(&shares) {
                        match storage
                            .put_object_if_match(
                                bucket,
                                &public_shares_key,
                                shares_bytes,
                                Some("application/json"),
                                &e_tag,
                            )
                            .await
                        {
                            Ok(true) => return,
                            Ok(false) => continue,
                            Err(_) => return,
                        }
                    }
                }
                return;
            }
            Ok(None) | Err(_) => return,
        }
    }
}

// Background cleanup worker - deletes objects using the configured share and partial-upload lifetimes.
async fn run_cleanup_worker(storage: storage::Storage, bucket: String) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // check every hour
    loop {
        interval.tick().await;
        tracing::info!(
            "Running S3 cleanup worker for expired shares and abandoned partial uploads..."
        );
        if let Err(e) = perform_cleanup(&storage, &bucket).await {
            tracing::error!("Error during cleanup execution: {:?}", e);
        }
    }
}

struct ShareGroup {
    has_owner: bool,
    owner_modified_secs: i64,
    latest_modified_secs: i64,
    keys: Vec<String>,
}

async fn perform_cleanup(
    storage: &storage::Storage,
    bucket: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Utc::now().timestamp();

    let share_expiry_days = std::env::var("DILLSHARE_EXPIRE_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(90)
        .clamp(1, 3650);
    let share_expire_limit = share_expiry_days * 24 * 60 * 60;

    let partial_timeout_hours = std::env::var("DILLSHARE_PARTIAL_TIMEOUT_HOURS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(12)
        .clamp(1, 168); // Hard lifetime for incomplete uploads, regardless of heartbeats
    let partial_upload_limit = partial_timeout_hours * 60 * 60;

    let mut groups: std::collections::HashMap<String, ShareGroup> =
        std::collections::HashMap::new();

    // Abort abandoned S3 multipart uploads that have seen no part activity
    // within the partial-upload timeout. These would otherwise leak storage
    // forever (S3 keeps them until a lifecycle rule or explicit abort).
    let partial_timeout_secs = partial_upload_limit;
    if let Ok(multipart_uploads) = storage.list_multipart_uploads(bucket).await {
        for mp in multipart_uploads {
            let age = now - mp.initiated_secs;
            if age > partial_timeout_secs {
                let active_key = mp
                    .key
                    .strip_prefix("uploads/")
                    .and_then(|rest| rest.split_once('/'))
                    .map(|(uuid, _)| format!("uploads/{}/.active", uuid));
                if let Some(active_key) = active_key {
                    if let Ok(Some(active)) = storage.head_object_info(bucket, &active_key).await {
                        if now - active.last_modified_secs <= partial_timeout_secs {
                            if let Ok(bytes) = storage.get_object_bytes(bucket, &active_key).await {
                                if let Ok(marker) =
                                    serde_json::from_slice::<ActiveUploadMarker>(&bytes)
                                {
                                    if now - marker.created_at <= partial_timeout_secs {
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
                tracing::info!(
                    "Aborting stale multipart upload '{}' for key '{}' (age: {}s).",
                    mp.upload_id,
                    mp.key,
                    age
                );
                let _ = storage
                    .abort_multipart_upload(bucket, &mp.key, &mp.upload_id)
                    .await;
            }
        }
    }

    let objects = storage.list_objects(bucket, Some("uploads/"), None).await?;
    for object in objects {
        let key = &object.key;
        let mod_secs = object.last_modified_secs;

        let rel = key.strip_prefix("uploads/").unwrap_or(key);
        let parts: Vec<&str> = rel.splitn(2, '/').collect();
        let uuid = if !parts.is_empty() {
            parts[0].to_string()
        } else {
            "root".to_string()
        };

        let entry = groups.entry(uuid).or_insert_with(|| ShareGroup {
            has_owner: false,
            owner_modified_secs: 0,
            latest_modified_secs: 0,
            keys: Vec::new(),
        });

        if rel.ends_with("/owner.txt") || rel == "owner.txt" {
            entry.has_owner = true;
            entry.owner_modified_secs = mod_secs;
        }
        if mod_secs > entry.latest_modified_secs {
            entry.latest_modified_secs = mod_secs;
        }
        entry.keys.push(key.to_string());
    }

    let mut keys_to_delete = Vec::new();
    let mut expired_share_uuids = Vec::new();

    for (uuid, group) in groups {
        if group.has_owner {
            let age = now - group.owner_modified_secs;
            if age > share_expire_limit {
                tracing::info!(
                    "Completed share '{}' is older than {} days (age: {}s). Marking for deletion.",
                    uuid,
                    share_expiry_days,
                    age
                );
                keys_to_delete.extend(group.keys);
                expired_share_uuids.push(uuid);
            } else {
                let manifest_key = format!("uploads/{}/{}", uuid, FINALIZED_MANIFEST_NAME);
                if let Ok(bytes) = storage.get_object_bytes(bucket, &manifest_key).await {
                    if let Ok(manifest) = serde_json::from_slice::<FinalizedShareManifest>(&bytes) {
                        let prefix = format!("uploads/{}/", uuid);
                        let mut allowed = std::collections::HashSet::new();
                        allowed.insert(format!("{}owner.txt", prefix));
                        allowed.insert(manifest_key);
                        for file_name in manifest.files.keys() {
                            allowed.insert(format!("{}{}", prefix, file_name));
                        }
                        keys_to_delete
                            .extend(group.keys.into_iter().filter(|key| !allowed.contains(key)));
                    }
                }
            }
        } else {
            let active_key = format!("uploads/{}/.active", uuid);
            let owner_key = format!("uploads/{}/owner.txt", uuid);
            match storage.head_object_info(bucket, &owner_key).await {
                Ok(None) => {}
                Ok(Some(_)) | Err(_) => continue,
            }

            let active_info = match storage.head_object_info(bucket, &active_key).await {
                Ok(info) => info,
                Err(_) => continue,
            };
            let mut created_at = group.latest_modified_secs;
            if let Some(active_info) = active_info {
                let bytes = match storage.get_object_bytes(bucket, &active_key).await {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                let mut marker = match serde_json::from_slice::<ActiveUploadMarker>(&bytes) {
                    Ok(marker) => marker,
                    Err(_) => continue,
                };
                created_at = marker.created_at;
                if now - created_at <= partial_upload_limit {
                    continue;
                }
                if marker.status == "active" || marker.status == "finishing" {
                    // Once the hard session lifetime has elapsed, even a crashed
                    // finisher must be reclaimable. CAS prevents racing a marker
                    // that changed after this cleanup worker read it.
                    let e_tag = match active_info.e_tag {
                        Some(e_tag) => e_tag,
                        None => continue,
                    };
                    marker.status = "cleaning".to_string();
                    let marker_bytes = match serde_json::to_vec(&marker) {
                        Ok(bytes) => bytes,
                        Err(_) => continue,
                    };
                    match storage
                        .put_object_if_match(
                            bucket,
                            &active_key,
                            marker_bytes,
                            Some("application/json"),
                            &e_tag,
                        )
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) | Err(_) => continue,
                    }
                } else if marker.status != "aborting" && marker.status != "cleaning" {
                    continue;
                }
            }
            let age = now - created_at;
            if age > partial_upload_limit {
                match storage.head_object_info(bucket, &owner_key).await {
                    Ok(None) => {}
                    Ok(Some(_)) | Err(_) => continue,
                }
                tracing::info!("Partial/cancelled upload '{}' has no owner record and is inactive (age: {}s). Marking for cleanup.", uuid, age);
                keys_to_delete.extend(group.keys);
            }
        }
    }

    // Prune expired shares from owner index files before deleting S3 objects
    for uuid in &expired_share_uuids {
        let owner_key = format!("uploads/{}/owner.txt", uuid);
        if let Ok(bytes) = storage.get_object_bytes(bucket, &owner_key).await {
            let owner = String::from_utf8(bytes.to_vec())
                .unwrap_or_default()
                .trim()
                .to_string();
            if !owner.is_empty() {
                remove_share_from_user_index(storage, bucket, &owner, uuid).await;
            }
        }
    }

    // Cleanup old auth sessions
    if let Ok(sessions) = storage
        .list_objects(bucket, Some("auth_sessions/"), None)
        .await
    {
        for session in sessions {
            if now - session.last_modified_secs > partial_upload_limit {
                keys_to_delete.push(session.key);
            }
        }
    }

    // Cleanup old user passkey states
    if let Ok(users) = storage.list_objects(bucket, Some("users/"), None).await {
        for object in users {
            if (object.key.ends_with("/passkey_reg.json")
                || object.key.ends_with("/passkey_auth.json"))
                && now - object.last_modified_secs > partial_upload_limit
            {
                keys_to_delete.push(object.key);
            }
        }
    }

    // Cleanup orphaned passkey indexes
    if let Ok(indexes) = storage
        .list_objects(bucket, Some("passkey_index/"), None)
        .await
    {
        for index in indexes {
            let cred_id_b64 = index
                .key
                .strip_prefix("passkey_index/")
                .unwrap_or(&index.key);
            let mut keep = false;
            if let Ok(bytes) = storage.get_object_bytes(bucket, &index.key).await {
                if let Ok(username) = String::from_utf8(bytes.to_vec()) {
                    let passkeys_key = format!("users/{}/passkeys.json", username.trim());
                    if let Ok(pk_bytes) = storage.get_object_bytes(bucket, &passkeys_key).await {
                        if let Ok(passkeys) =
                            serde_json::from_slice::<Vec<webauthn_rs::prelude::Passkey>>(&pk_bytes)
                        {
                            use base64::Engine;
                            keep = passkeys.iter().any(|pk| {
                                base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(pk.cred_id())
                                    == cred_id_b64
                            });
                        }
                    }
                }
            }
            if !keep {
                keys_to_delete.push(index.key);
            }
        }
    }

    // Full bucket scan for completely foreign files and orphaned user data
    if let Ok(all_objects) = storage.list_objects(bucket, None, None).await {
        let mut valid_users = std::collections::HashSet::new();
        for object in &all_objects {
            if object.key.starts_with("users/") {
                let parts: Vec<&str> = object.key.split('/').collect();
                if parts.len() == 2 && object.key.ends_with(".json") {
                    if let Some(username) = parts[1].strip_suffix(".json") {
                        valid_users.insert(username.to_string());
                    }
                }
            }
        }

        for object in all_objects {
            let key = object.key;
            if key.starts_with("config/")
                || key.starts_with("admin/")
                || key.starts_with("uploads/")
                || key.starts_with("auth_sessions/")
                || key.starts_with("passkey_index/")
            {
                continue;
            }

            if key.starts_with("users/") {
                let parts: Vec<&str> = key.split('/').collect();
                if parts.len() == 2 && key.ends_with(".json") {
                    continue;
                } else if parts.len() == 3 {
                    let username = parts[1];
                    let filename = parts[2];
                    if valid_users.contains(username) {
                        let allowed_files = [
                            "passkeys.json",
                            "passkeys_meta.json",
                            "sessions.json",
                            "public_shares.json",
                            "pfp.enc",
                            "passkey_reg.json",
                            "passkey_auth.json",
                        ];
                        if allowed_files.contains(&filename) {
                            continue;
                        }
                    }
                }
            }

            keys_to_delete.push(key);
        }
    }

    keys_to_delete.sort();
    keys_to_delete.dedup();

    if !keys_to_delete.is_empty() {
        tracing::info!(
            "Deleting {} expired/partial S3 objects...",
            keys_to_delete.len()
        );
        // Batch delete in chunks of 1000 keys per request (S3's DeleteObjects
        // limit) instead of one round trip per object.
        for chunk in keys_to_delete.chunks(1000) {
            let _ = storage.delete_objects_batch(bucket, chunk).await;
        }
        tracing::info!("Cleanup sweep finished successfully.");
    } else {
        tracing::info!("Cleanup sweep completed. No expired or partial objects found.");
    }

    Ok(())
}

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

const ADMIN_ROLES_KEY: &str = "config/admin_roles.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AdminRoles {
    version: u8,
    superadmin: String,
    #[serde(default)]
    admins: std::collections::BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccountRole {
    User,
    Admin,
    Superadmin,
}

impl AccountRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Superadmin => "superadmin",
        }
    }
}

impl AdminRoles {
    fn role_for(&self, username: &str) -> AccountRole {
        if self.superadmin == username {
            AccountRole::Superadmin
        } else if self.admins.contains(username) {
            AccountRole::Admin
        } else {
            AccountRole::User
        }
    }
}

fn parse_admin_roles(bytes: &[u8]) -> Result<AdminRoles, String> {
    let mut roles: AdminRoles = serde_json::from_slice(bytes)
        .map_err(|error| format!("Invalid administrator role data: {error}"))?;
    if roles.version != 1 || !is_valid_username(&roles.superadmin) {
        return Err("Invalid administrator role data".to_string());
    }
    roles
        .admins
        .retain(|username| is_valid_username(username) && username != &roles.superadmin);
    Ok(roles)
}

async fn load_admin_roles_from_storage(
    storage: &storage::Storage,
    bucket: &str,
) -> Result<Option<AdminRoles>, String> {
    match storage.get_object_bytes(bucket, ADMIN_ROLES_KEY).await {
        Ok(bytes) => parse_admin_roles(&bytes).map(Some),
        Err(error) => {
            if storage
                .head_object_info(bucket, ADMIN_ROLES_KEY)
                .await?
                .is_none()
            {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }
}

async fn initialize_admin_roles(storage: &storage::Storage, bucket: &str) -> Result<(), String> {
    if load_admin_roles_from_storage(storage, bucket)
        .await?
        .is_some()
    {
        return Ok(());
    }

    // Existing installations predate role metadata. Select the oldest top-level
    // account object as the deterministic migration equivalent of the first signup.
    let mut users: Vec<(i64, String)> = storage
        .list_objects(bucket, Some("users/"), None)
        .await?
        .into_iter()
        .filter_map(|object| {
            let relative = object.key.strip_prefix("users/")?;
            if relative.contains('/') {
                return None;
            }
            let username = relative.strip_suffix(".json")?;
            is_valid_username(username).then(|| (object.last_modified_secs, username.to_string()))
        })
        .collect();
    users.sort_by(|left, right| left.cmp(right));
    let Some((_, username)) = users.into_iter().next() else {
        return Ok(());
    };

    let roles = AdminRoles {
        version: 1,
        superadmin: username.clone(),
        admins: std::collections::BTreeSet::new(),
    };
    let created = storage
        .put_object_if_absent(
            bucket,
            ADMIN_ROLES_KEY,
            serde_json::to_vec(&roles).map_err(|error| error.to_string())?,
            Some("application/json"),
        )
        .await?;
    if created {
        tracing::warn!(
            superadmin = username,
            "Migrated existing installation: oldest account is now superadmin"
        );
    }
    Ok(())
}

async fn claim_superadmin_if_first(
    state: &AppState,
    username: &str,
) -> Result<AccountRole, String> {
    let roles = AdminRoles {
        version: 1,
        superadmin: username.to_string(),
        admins: std::collections::BTreeSet::new(),
    };
    let created = match state
        .storage
        .put_object_if_absent(
            &state.bucket,
            ADMIN_ROLES_KEY,
            serde_json::to_vec(&roles).map_err(|error| error.to_string())?,
            Some("application/json"),
        )
        .await
    {
        Ok(created) => created,
        Err(write_error) => {
            // A timed-out conditional write may still have reached object storage.
            // Read back before reporting an error so we never delete the account
            // that successfully became superadmin.
            if let Some(current) =
                load_admin_roles_from_storage(&state.storage, &state.bucket).await?
            {
                return Ok(current.role_for(username));
            }
            return Err(write_error);
        }
    };
    if created {
        tracing::info!(
            superadmin = username,
            "First account claimed superadmin role"
        );
        Ok(AccountRole::Superadmin)
    } else {
        let roles = load_admin_roles_from_storage(&state.storage, &state.bucket)
            .await?
            .ok_or_else(|| "Administrator role data disappeared".to_string())?;
        Ok(roles.role_for(username))
    }
}

async fn account_role(state: &AppState, username: &str) -> Result<AccountRole, String> {
    Ok(load_admin_roles_from_storage(&state.storage, &state.bucket)
        .await?
        .map(|roles| roles.role_for(username))
        .unwrap_or(AccountRole::User))
}

async fn update_promoted_admin(
    state: &AppState,
    username: &str,
    promote: bool,
) -> Result<(), (StatusCode, String)> {
    for _ in 0..5 {
        let Some((bytes, e_tag)) = state
            .storage
            .get_object_bytes_with_etag(&state.bucket, ADMIN_ROLES_KEY)
            .await
            .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?
        else {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Administrator roles are not initialized".to_string(),
            ));
        };
        let mut roles = parse_admin_roles(&bytes)
            .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
        if roles.superadmin == username {
            return Err((
                StatusCode::CONFLICT,
                "The superadmin role cannot be changed".to_string(),
            ));
        }
        if promote {
            roles.admins.insert(username.to_string());
        } else {
            roles.admins.remove(username);
        }
        let updated = state
            .storage
            .put_object_if_match(
                &state.bucket,
                ADMIN_ROLES_KEY,
                serde_json::to_vec(&roles)
                    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?,
                Some("application/json"),
                &e_tag,
            )
            .await
            .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
        if updated {
            return Ok(());
        }
    }
    Err((
        StatusCode::CONFLICT,
        "Administrator roles changed concurrently; retry".to_string(),
    ))
}

#[derive(Debug)]
struct AdminIdentity {
    username: String,
    role: AccountRole,
}

async fn verify_admin(
    headers: &axum::http::HeaderMap,
    state: &AppState,
) -> Result<AdminIdentity, (StatusCode, String)> {
    let token = extract_token(headers)?;
    let (username, _) = verify_session(&token, state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;
    let role = account_role(state, &username)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
    if role == AccountRole::User {
        return Err((
            StatusCode::FORBIDDEN,
            "Administrator access required".to_string(),
        ));
    }
    Ok(AdminIdentity { username, role })
}

#[derive(serde::Deserialize)]
struct AuthRequest {
    username: String,
    auth_key: String,
    #[serde(default)]
    totp_code: Option<String>,
}

#[derive(serde::Deserialize)]
struct Setup2FARequest {
    code: String,
    secret: String,
}

#[derive(serde::Deserialize)]
struct Disable2FARequest {
    code: String,
}

#[derive(serde::Deserialize)]
struct SaveSharesRequest {
    shares_enc: String,
}

fn verify_totp_code(
    secret: &str,
    username: &str,
    code: &str,
) -> Result<bool, (StatusCode, String)> {
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(false);
    }
    let secret = totp_rs::Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid 2FA configuration".to_string(),
            )
        })?;
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("DillShare".to_string()),
        username.to_string(),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid 2FA configuration".to_string(),
        )
    })?;
    totp.check_current(code).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "2FA verification failed".to_string(),
        )
    })
}

async fn register_user(
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<AuthRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let username = payload.username.trim();
    if !is_valid_username(username) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username must be 3-30 letters, numbers, dashes, or underscores".to_string(),
        ));
    }
    if !is_valid_auth_key(&payload.auth_key) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid authentication key".to_string(),
        ));
    }

    let user_key = format!("users/{}.json", username);

    // Hash the auth_key with a server salt
    let mut hasher = Sha256::new();
    hasher.update(payload.auth_key.as_bytes());
    hasher.update(b"server-salt-dill-share");
    let password_hash = format!("{:02x}", hasher.finalize());

    let user_data = serde_json::json!({
        "password_hash": password_hash,
        "created_at": chrono::Utc::now().timestamp()
    });
    let user_bytes = serde_json::to_vec(&user_data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // A conditional write prevents concurrent registrations from overwriting
    // one another after a check-then-write race.
    let created = state
        .storage
        .put_object_if_absent(
            &state.bucket,
            &user_key,
            user_bytes,
            Some("application/json"),
        )
        .await
        .map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save user: {error}"),
            )
        })?;
    if !created {
        return Err((
            StatusCode::CONFLICT,
            "Username is already taken".to_string(),
        ));
    }

    if let Err(error) = claim_superadmin_if_first(&state, username).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Account was created, but its role could not be assigned: {error}"),
        ));
    }

    Ok(StatusCode::CREATED)
}

async fn login_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<AuthRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let username = payload.username.trim();
    if !is_valid_username(username) || !is_valid_auth_key(&payload.auth_key) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid username or password".to_string(),
        ));
    }
    let user_key = format!("users/{}.json", username);

    // Retrieve user data from S3
    let bytes = state
        .storage
        .get_object_bytes(&state.bucket, &user_key)
        .await
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Invalid username or password".to_string(),
            )
        })?;
    let user_json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let stored_hash = user_json
        .get("password_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid user profile data in S3".to_string(),
            )
        })?;

    // Check password hash
    let mut hasher = Sha256::new();
    hasher.update(payload.auth_key.as_bytes());
    hasher.update(b"server-salt-dill-share");
    let computed_hash = format!("{:02x}", hasher.finalize());

    if !secure_equal(computed_hash.as_bytes(), stored_hash.as_bytes()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid username or password".to_string(),
        ));
    }

    let totp_enabled = user_json
        .get("totp_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if totp_enabled {
        let totp_secret = user_json
            .get("totp_secret")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some(code) = &payload.totp_code {
            if !verify_totp_code(totp_secret, username, code)? {
                return Err((StatusCode::FORBIDDEN, "INVALID_2FA".to_string()));
            }
        } else {
            return Err((StatusCode::FORBIDDEN, "2FA_REQUIRED".to_string()));
        }
    }

    // Generate token with a unique session id (sessions never expire)
    let session_id = uuid::Uuid::new_v4().to_string();
    let expiry = 0;
    let token = generate_token(username, &state.jwt_secret, expiry, &session_id);

    let (user_agent, ip) = request_client_metadata(&headers);

    let new_session = UserSession {
        id: session_id,
        created_at: chrono::Utc::now().timestamp(),
        user_agent,
        ip,
        expires_at: expiry,
        name: None,
    };

    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, &sessions_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    sessions.push(new_session);
    if sessions.len() > MAX_SESSIONS_PER_ACCOUNT {
        sessions.sort_by_key(|session| session.created_at);
        sessions.drain(..sessions.len() - MAX_SESSIONS_PER_ACCOUNT);
    }

    if let Ok(session_bytes) = serde_json::to_vec(&sessions) {
        let _ = state
            .storage
            .put_object(
                &state.bucket,
                &sessions_key,
                session_bytes,
                Some("application/json"),
            )
            .await;
    }

    let pfp_enc = fetch_user_pfp_enc(&state, username).await;
    let role = account_role(&state, username)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;

    Ok(axum::Json(serde_json::json!({
        "token": token,
        "role": role.as_str(),
        "pfp_enc": pfp_enc,
        "pfp": pfp_enc
    })))
}

async fn get_user_shares(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let shares_key = format!("users/{}/shares.enc", username);

    // Fetch from S3
    let bytes = state
        .storage
        .get_object_bytes(&state.bucket, &shares_key)
        .await;

    match bytes {
        Ok(bytes) => {
            // Hex encode to send in JSON
            let shares_hex = bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            Ok(axum::Json(serde_json::json!({ "shares_enc": shares_hex })))
        }
        Err(_) => {
            // S3 NoSuchKey means no shares yet
            Ok(axum::Json(serde_json::json!({ "shares_enc": "" })))
        }
    }
}

async fn save_user_shares(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<SaveSharesRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let bytes = decode_hex(payload.shares_enc.trim(), USER_DATA_MAX_BYTES)?;

    let shares_key = format!("users/{}/shares.enc", username);

    // Write to S3
    state
        .storage
        .put_object(
            &state.bucket,
            &shares_key,
            bytes,
            Some("application/octet-stream"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save shares to S3: {:?}", e),
            )
        })?;

    Ok(StatusCode::OK)
}

fn extract_token(headers: &axum::http::HeaderMap) -> Result<String, (StatusCode, String)> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Authorization header is missing".to_string(),
            )
        })?;

    let auth_str = auth_header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid authorization header characters".to_string(),
        )
    })?;

    let token = auth_str.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authorization scheme must be Bearer".to_string(),
        )
    })?;
    if token.is_empty() || token.len() > 4096 {
        return Err((StatusCode::UNAUTHORIZED, "Invalid token".to_string()));
    }

    Ok(token.to_string())
}

type HmacSha256 = Hmac<Sha256>;

fn secure_equal(left: &[u8], right: &[u8]) -> bool {
    let Ok(mut left_mac) = HmacSha256::new_from_slice(left) else {
        return false;
    };
    left_mac.update(b"dillshare constant-time comparison");
    let expected = left_mac.finalize().into_bytes();
    let Ok(mut right_mac) = HmacSha256::new_from_slice(right) else {
        return false;
    };
    right_mac.update(b"dillshare constant-time comparison");
    right_mac.verify_slice(&expected).is_ok()
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct UserSession {
    id: String,
    created_at: i64,
    user_agent: String,
    ip: String,
    expires_at: i64,
    #[serde(default)]
    name: Option<String>,
}

fn generate_token(
    username: &str,
    secret: &[u8],
    expiry_timestamp: i64,
    session_id: &str,
) -> String {
    let payload = format!("{}:{}:{}", username, expiry_timestamp, session_id);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    let signature = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let username_hex = username
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    format!(
        "{}.{}.{}.{}",
        username_hex, expiry_timestamp, session_id, signature
    )
}

fn verify_token_signature(token: &str, secret: &[u8]) -> Option<(String, i64, String)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let username_hex = parts[0];
    let expiry_str = parts[1];
    let session_id = parts[2];
    let signature = parts[3];

    let expiry_timestamp = expiry_str.parse::<i64>().ok()?;

    let username = String::from_utf8(decode_hex(username_hex, 128).ok()?).ok()?;
    if !is_valid_username(&username) || !is_canonical_uuid(session_id) {
        return None;
    }
    if expiry_timestamp != 0 && chrono::Utc::now().timestamp() >= expiry_timestamp {
        return None;
    }
    let signature = decode_hex(signature, 32).ok()?;
    if signature.len() != 32 {
        return None;
    }

    let payload = format!("{}:{}:{}", username, expiry_timestamp, session_id);
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature).ok()?;
    Some((username, expiry_timestamp, session_id.to_string()))
}

async fn verify_session(token: &str, state: &AppState) -> Option<(String, String)> {
    let (username, _expiry, session_id) = verify_token_signature(token, &state.jwt_secret)?;

    let sessions_key = format!("users/{}/sessions.json", username);
    let res = state
        .storage
        .get_object_bytes(&state.bucket, &sessions_key)
        .await;

    match res {
        Ok(bytes) => {
            let sessions: Vec<UserSession> = serde_json::from_slice(&bytes).ok()?;

            let exists = sessions.iter().any(|s| s.id == session_id);
            if exists {
                Some((username, session_id))
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

// --- ADMIN HANDLERS ---

async fn admin_get_stats(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let identity = verify_admin(&headers, &state).await?;
    let roles = load_admin_roles_from_storage(&state.storage, &state.bucket)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Administrator roles are not initialized".to_string(),
            )
        })?;

    let objects = state
        .storage
        .list_objects(&state.bucket, Some("users/"), None)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let mut users_list = Vec::new();
    for object in objects {
        let key = &object.key;
        if key.starts_with("users/") && key.ends_with(".json") {
            let relative = key.strip_prefix("users/").unwrap_or(key);
            if !relative.contains('/') {
                let username = relative
                    .strip_suffix(".json")
                    .unwrap_or(relative)
                    .to_string();
                if is_valid_username(&username) {
                    users_list.push(username);
                }
            }
        }
    }

    let mut stats = Vec::new();

    for username in users_list {
        let public_shares_key = format!("users/{}/public_shares.json", username);
        let shares = match state
            .storage
            .get_object_bytes(&state.bucket, &public_shares_key)
            .await
        {
            Ok(bytes) => {
                serde_json::from_slice::<Vec<serde_json::Value>>(&bytes).unwrap_or_default()
            }
            Err(_) => Vec::new(),
        };

        let user_key = format!("users/{}.json", username);
        let totp_enabled = match state
            .storage
            .get_object_bytes(&state.bucket, &user_key)
            .await
        {
            Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
                .unwrap_or_default()
                .get("totp_enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            Err(_) => false,
        };

        let total_size: i64 = shares
            .iter()
            .map(|s| {
                s.get("stored_size")
                    .or_else(|| s.get("total_size"))
                    .and_then(|size| size.as_i64())
                    .unwrap_or(0)
            })
            .sum();

        stats.push(serde_json::json!({
            "role": roles.role_for(&username).as_str(),
            "username": username,
            "total_size": total_size,
            "shares": shares,
            "has_2fa": totp_enabled
        }));
    }
    stats.sort_by(|left, right| {
        left.get("username")
            .and_then(|value| value.as_str())
            .cmp(&right.get("username").and_then(|value| value.as_str()))
    });

    Ok(axum::Json(serde_json::json!({
        "current_user": identity.username,
        "current_role": identity.role.as_str(),
        "users": stats
    })))
}

async fn admin_delete_share(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;
    validate_upload_uuid(&uuid)?;

    let owner_key = format!("uploads/{}/owner.txt", uuid);
    let owner_res = state
        .storage
        .get_object_bytes(&state.bucket, &owner_key)
        .await;

    let owner = match owner_res {
        Ok(bytes) => String::from_utf8(bytes)
            .unwrap_or_default()
            .trim()
            .to_string(),
        Err(_) => String::new(),
    };

    delete_share_objects(&state.storage, &state.bucket, &uuid).await?;

    if !owner.is_empty() {
        remove_share_from_user_index(&state.storage, &state.bucket, &owner, &uuid).await;
    } else {
        if let Ok(response) = state
            .storage
            .list_objects(&state.bucket, Some("users/"), None)
            .await
        {
            for object in response {
                if object.key.ends_with("/public_shares.json") {
                    if let Some(user_part) = object
                        .key
                        .strip_prefix("users/")
                        .and_then(|key| key.strip_suffix("/public_shares.json"))
                    {
                        remove_share_from_user_index(
                            &state.storage,
                            &state.bucket,
                            user_part,
                            &uuid,
                        )
                        .await;
                    }
                }
            }
        }
    }

    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
struct AdminRoleUpdate {
    role: String,
}

async fn admin_set_user_role(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(username): Path<String>,
    axum::Json(payload): axum::Json<AdminRoleUpdate>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let identity = verify_admin(&headers, &state).await?;
    if identity.role != AccountRole::Superadmin {
        return Err((
            StatusCode::FORBIDDEN,
            "Only the superadmin can change administrator roles".to_string(),
        ));
    }
    let username = username.trim();
    if !is_valid_username(username) {
        return Err((StatusCode::BAD_REQUEST, "Invalid username".to_string()));
    }
    if state
        .storage
        .head_object_info(&state.bucket, &format!("users/{username}.json"))
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
    }
    let promote = match payload.role.as_str() {
        "admin" => true,
        "user" => false,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "Role must be admin or user".to_string(),
            ))
        }
    };
    update_promoted_admin(&state, username, promote).await?;
    Ok(axum::Json(serde_json::json!({
        "username": username,
        "role": if promote { "admin" } else { "user" }
    })))
}

async fn admin_delete_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let identity = verify_admin(&headers, &state).await?;

    let username = username.trim();
    if !is_valid_username(username) {
        return Err((StatusCode::BAD_REQUEST, "Invalid username".to_string()));
    }
    let target_role = account_role(&state, username)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
    if target_role == AccountRole::Superadmin {
        return Err((
            StatusCode::FORBIDDEN,
            "The superadmin account cannot be deleted".to_string(),
        ));
    }
    if target_role == AccountRole::Admin && identity.role != AccountRole::Superadmin {
        return Err((
            StatusCode::FORBIDDEN,
            "Only the superadmin can delete an administrator".to_string(),
        ));
    }

    let public_shares_key = format!("users/{}/public_shares.json", username);
    if let Ok(bytes) = state
        .storage
        .get_object_bytes(&state.bucket, &public_shares_key)
        .await
    {
        if let Ok(shares) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
            for share in shares {
                if let Some(uuid) = share
                    .get("uuid")
                    .and_then(|value| value.as_str())
                    .filter(|uuid| is_canonical_uuid(uuid))
                {
                    delete_share_objects(&state.storage, &state.bucket, uuid).await?;
                }
            }
        }
    }

    let user_profile_key = format!("users/{}.json", username);
    let user_folder_prefix = format!("users/{}/", username);

    state
        .storage
        .delete_object(&state.bucket, &user_profile_key)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
    delete_s3_prefix(&state.storage, &state.bucket, &user_folder_prefix).await?;
    if target_role == AccountRole::Admin {
        update_promoted_admin(&state, username, false).await?;
    }

    Ok(StatusCode::OK)
}

async fn delete_s3_prefix(
    storage: &storage::Storage,
    bucket: &str,
    prefix: &str,
) -> Result<(), (StatusCode, String)> {
    let keys = storage
        .list_objects(bucket, Some(prefix), None)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let key_names: Vec<String> = keys.into_iter().map(|k| k.key).collect();
    if !key_names.is_empty() {
        storage
            .delete_objects_batch(bucket, &key_names)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }
    Ok(())
}

async fn delete_share_objects(
    storage: &storage::Storage,
    bucket: &str,
    uuid: &str,
) -> Result<(), (StatusCode, String)> {
    let prefix = format!("uploads/{}/", uuid);
    delete_s3_prefix(storage, bucket, &prefix).await?;

    let info_key = format!("shares/{}.json", uuid);
    let _ = storage.delete_object(bucket, &info_key).await;

    Ok(())
}

async fn fetch_user_pfp_enc(state: &AppState, username: &str) -> String {
    let pfp_key = format!("users/{}/pfp.enc", username);
    match state
        .storage
        .get_object_bytes(&state.bucket, &pfp_key)
        .await
    {
        Ok(bytes) => bytes
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>(),
        Err(_) => String::new(),
    }
}

async fn get_user_profile(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let pfp_enc = fetch_user_pfp_enc(&state, &username).await;

    let user_key = format!("users/{}.json", username);
    let mut totp_enabled = false;
    if let Ok(bytes) = state
        .storage
        .get_object_bytes(&state.bucket, &user_key)
        .await
    {
        if let Ok(user_json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            totp_enabled = user_json
                .get("totp_enabled")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
        }
    }

    let role = account_role(&state, &username)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;

    Ok(axum::Json(serde_json::json!({
        "username": username,
        "role": role.as_str(),
        "pfp_enc": pfp_enc,
        "pfp": pfp_enc,
        "totp_enabled": totp_enabled
    })))
}

#[derive(serde::Deserialize)]
struct SaveProfileRequest {
    #[serde(default)]
    pfp_enc: String,
    #[serde(default)]
    pfp: String,
}

async fn save_user_profile(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<SaveProfileRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    // Clean up legacy base64 pfp from users/{username}.json if present
    let user_key = format!("users/{}.json", username);
    if let Ok(bytes) = state
        .storage
        .get_object_bytes(&state.bucket, &user_key)
        .await
    {
        if let Ok(mut user_json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(object) = user_json.as_object_mut() {
                if object.remove("pfp").is_some() {
                    if let Ok(user_bytes) = serde_json::to_vec(&user_json) {
                        let _ = state
                            .storage
                            .put_object(
                                &state.bucket,
                                &user_key,
                                user_bytes,
                                Some("application/json"),
                            )
                            .await;
                    }
                }
            }
        }
    }

    let hex_data = if !payload.pfp_enc.is_empty() {
        payload.pfp_enc
    } else {
        payload.pfp
    };

    let pfp_key = format!("users/{}/pfp.enc", username);

    if hex_data.trim().is_empty() {
        let _ = state.storage.delete_object(&state.bucket, &pfp_key).await;
    } else {
        let bytes = decode_hex(hex_data.trim(), USER_DATA_MAX_BYTES)?;

        state
            .storage
            .put_object(
                &state.bucket,
                &pfp_key,
                bytes,
                Some("application/octet-stream"),
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to update profile picture: {:?}", e),
                )
            })?;
    }

    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
struct ChangePasswordRequest {
    current_auth_key: String,
    new_auth_key: String,
    new_shares_enc: String,
    #[serde(default)]
    new_pfp_enc: Option<String>,
}

async fn user_change_password(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, current_session_id) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    if !is_valid_auth_key(&payload.current_auth_key) || !is_valid_auth_key(&payload.new_auth_key) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid authentication key".to_string(),
        ));
    }
    // Validate every encrypted replacement before changing any stored value.
    let new_shares_bytes = decode_hex(payload.new_shares_enc.trim(), USER_DATA_MAX_BYTES)?;
    let new_pfp_bytes = payload
        .new_pfp_enc
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| decode_hex(value.trim(), USER_DATA_MAX_BYTES))
        .transpose()?;

    let user_key = format!("users/{}.json", username);

    let bytes = state
        .storage
        .get_object_bytes(&state.bucket, &user_key)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "User profile not found".to_string()))?;
    let mut user_json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let stored_hash = user_json
        .get("password_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid user profile data in S3".to_string(),
            )
        })?;

    let mut hasher = Sha256::new();
    hasher.update(payload.current_auth_key.as_bytes());
    hasher.update(b"server-salt-dill-share");
    let computed_hash = format!("{:02x}", hasher.finalize());

    if !secure_equal(computed_hash.as_bytes(), stored_hash.as_bytes()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Incorrect current password".to_string(),
        ));
    }

    let mut new_hasher = Sha256::new();
    new_hasher.update(payload.new_auth_key.as_bytes());
    new_hasher.update(b"server-salt-dill-share");
    let new_password_hash = format!("{:02x}", new_hasher.finalize());

    if let Some(obj) = user_json.as_object_mut() {
        obj.insert(
            "password_hash".to_string(),
            serde_json::Value::String(new_password_hash),
        );
    }

    let user_bytes = serde_json::to_vec(&user_json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .storage
        .put_object(
            &state.bucket,
            &user_key,
            user_bytes,
            Some("application/json"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update profile: {:?}", e),
            )
        })?;

    let enc_bytes = new_shares_bytes;

    let shares_key = format!("users/{}/shares.enc", username);
    state
        .storage
        .put_object(
            &state.bucket,
            &shares_key,
            enc_bytes,
            Some("application/octet-stream"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save new shares: {:?}", e),
            )
        })?;

    if let Some(ref new_pfp) = payload.new_pfp_enc {
        let pfp_key = format!("users/{}/pfp.enc", username);
        if new_pfp.trim().is_empty() {
            let _ = state.storage.delete_object(&state.bucket, &pfp_key).await;
        } else {
            let bytes = new_pfp_bytes.clone().ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "Invalid profile picture".to_string(),
                )
            })?;
            state
                .storage
                .put_object(
                    &state.bucket,
                    &pfp_key,
                    bytes,
                    Some("application/octet-stream"),
                )
                .await
                .map_err(|error| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to save new profile picture: {error}"),
                    )
                })?;
        }
    }

    // Revoke all OTHER sessions of this user upon password change (forces relogin on other devices)
    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, &sessions_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    sessions.retain(|s| s.id == current_session_id);

    if let Ok(session_bytes) = serde_json::to_vec(&sessions) {
        let _ = state
            .storage
            .put_object(
                &state.bucket,
                &sessions_key,
                session_bytes,
                Some("application/json"),
            )
            .await;
    }

    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
struct DeleteAccountRequest {
    auth_key: String,
    #[serde(default)]
    totp_code: Option<String>,
}

async fn user_delete_account(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<DeleteAccountRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;
    let role = account_role(&state, &username)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
    if role == AccountRole::Superadmin {
        return Err((
            StatusCode::FORBIDDEN,
            "The superadmin account cannot be deleted".to_string(),
        ));
    }
    if !is_valid_auth_key(&payload.auth_key) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid authentication key".to_string(),
        ));
    }

    let user_profile_key = format!("users/{}.json", username);
    let user_bytes = state
        .storage
        .get_object_bytes(&state.bucket, &user_profile_key)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "User profile not found".to_string()))?;
    let user_json: serde_json::Value = serde_json::from_slice(&user_bytes)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let stored_hash = user_json
        .get("password_hash")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid user profile data in S3".to_string(),
            )
        })?;

    let mut hasher = Sha256::new();
    hasher.update(payload.auth_key.as_bytes());
    hasher.update(b"server-salt-dill-share");
    let computed_hash = format!("{:02x}", hasher.finalize());
    if !secure_equal(computed_hash.as_bytes(), stored_hash.as_bytes()) {
        return Err((
            StatusCode::FORBIDDEN,
            "Incorrect account password".to_string(),
        ));
    }

    let totp_enabled = user_json
        .get("totp_enabled")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if totp_enabled {
        let totp_secret = user_json
            .get("totp_secret")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let totp_code = payload
            .totp_code
            .as_deref()
            .map(str::trim)
            .filter(|code| !code.is_empty())
            .ok_or_else(|| {
                (
                    StatusCode::FORBIDDEN,
                    "Two-factor authentication code is required".to_string(),
                )
            })?;
        if !verify_totp_code(totp_secret, &username, totp_code)? {
            return Err((
                StatusCode::FORBIDDEN,
                "Invalid two-factor authentication code".to_string(),
            ));
        }
    }

    let public_shares_key = format!("users/{}/public_shares.json", username);
    if let Ok(bytes) = state
        .storage
        .get_object_bytes(&state.bucket, &public_shares_key)
        .await
    {
        if let Ok(shares) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
            for share in shares {
                if let Some(uuid) = share
                    .get("uuid")
                    .and_then(|value| value.as_str())
                    .filter(|uuid| is_canonical_uuid(uuid))
                {
                    delete_share_objects(&state.storage, &state.bucket, uuid).await?;
                }
            }
        }
    }

    let user_folder_prefix = format!("users/{}/", username);

    state
        .storage
        .delete_object(&state.bucket, &user_profile_key)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
    delete_s3_prefix(&state.storage, &state.bucket, &user_folder_prefix).await?;
    if role == AccountRole::Admin {
        update_promoted_admin(&state, &username, false).await?;
    }

    Ok(StatusCode::OK)
}

async fn load_or_create_jwt_secret(
    storage: &storage::Storage,
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, String> {
    if storage.head_object_info(bucket, key).await?.is_some() {
        let secret = storage.get_object_bytes(bucket, key).await?;
        if secret.len() < 32 {
            return Err("persisted JWT secret is too short".to_string());
        }
        return Ok(secret);
    }

    let mut secret = [0u8; 32];
    use rand::Rng;
    rand::rng().fill_bytes(&mut secret);
    if storage
        .put_object_if_absent(bucket, key, secret.to_vec(), None)
        .await?
    {
        Ok(secret.to_vec())
    } else {
        let existing = storage.get_object_bytes(bucket, key).await?;
        if existing.len() < 32 {
            Err("persisted JWT secret is too short".to_string())
        } else {
            Ok(existing)
        }
    }
}

async fn get_user_sessions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, current_session_id) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let sessions_key = format!("users/{}/sessions.json", username);
    let sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, &sessions_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    let mut response_sessions = Vec::new();

    for s in sessions {
        let is_current = s.id == current_session_id;
        response_sessions.push(serde_json::json!({
            "id": s.id,
            "created_at": s.created_at,
            "user_agent": s.user_agent,
            "ip": s.ip,
            "expires_at": s.expires_at,
            "is_current": is_current,
            "name": s.name,
        }));
    }

    Ok(axum::Json(response_sessions))
}

async fn revoke_user_session(
    State(state): State<AppState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _current_session_id) =
        verify_session(&token, &state).await.ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired session".to_string(),
            )
        })?;

    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, &sessions_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    let original_len = sessions.len();
    sessions.retain(|s| s.id != session_id);

    if sessions.len() < original_len {
        let session_bytes = serde_json::to_vec(&sessions)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        state
            .storage
            .put_object(
                &state.bucket,
                &sessions_key,
                session_bytes,
                Some("application/json"),
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to update sessions: {:?}", e),
                )
            })?;
    }

    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
struct RenameSessionRequest {
    name: String,
}

async fn rename_user_session(
    State(state): State<AppState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<RenameSessionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _current_session_id) =
        verify_session(&token, &state).await.ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired session".to_string(),
            )
        })?;

    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, &sessions_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    let clean_name = payload.name.trim();
    let truncated_name: String = clean_name.chars().take(32).collect();
    let new_name_opt = if truncated_name.is_empty() {
        None
    } else {
        Some(truncated_name)
    };

    let mut updated = false;
    for s in sessions.iter_mut() {
        if s.id == session_id {
            s.name = new_name_opt.clone();
            updated = true;
            break;
        }
    }

    if updated {
        let session_bytes = serde_json::to_vec(&sessions)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        state
            .storage
            .put_object(
                &state.bucket,
                &sessions_key,
                session_bytes,
                Some("application/json"),
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to update session: {:?}", e),
                )
            })?;
    }

    Ok(StatusCode::OK)
}

async fn admin_get_user_sessions(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let sessions_key = format!("users/{}/sessions.json", username);
    let sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, &sessions_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    let mut response_sessions = Vec::new();

    for s in sessions {
        response_sessions.push(serde_json::json!({
            "id": s.id,
            "created_at": s.created_at,
            "user_agent": s.user_agent,
            "ip": s.ip,
            "expires_at": s.expires_at,
            "is_current": false,
            "name": s.name,
        }));
    }

    Ok(axum::Json(response_sessions))
}

async fn admin_revoke_user_session(
    State(state): State<AppState>,
    Path((username, session_id)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, &sessions_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    let original_len = sessions.len();
    sessions.retain(|s| s.id != session_id);

    if sessions.len() < original_len {
        let session_bytes = serde_json::to_vec(&sessions)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        state
            .storage
            .put_object(
                &state.bucket,
                &sessions_key,
                session_bytes,
                Some("application/json"),
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to update sessions: {:?}", e),
                )
            })?;
    }

    Ok(StatusCode::OK)
}

async fn setup_2fa_init(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let secret = totp_rs::Secret::generate_secret();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to encode TOTP secret".to_string(),
            )
        })?,
        Some("DillShare".to_string()),
        username,
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create TOTP".to_string(),
        )
    })?;

    let qr = totp.get_qr_base64().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate QR code".to_string(),
        )
    })?;

    Ok(axum::Json(serde_json::json!({
        "secret": secret.to_encoded().to_string(),
        "qr_base64": qr
    })))
}

async fn setup_2fa_confirm(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<Setup2FARequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    if payload.secret.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "Invalid secret".to_string()));
    }
    let secret = totp_rs::Secret::Encoded(payload.secret.clone());
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret
            .to_bytes()
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid secret".to_string()))?,
        Some("DillShare".to_string()),
        username.clone(),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create TOTP".to_string(),
        )
    })?;

    if !totp.check_current(&payload.code).unwrap_or(false) {
        return Err((StatusCode::BAD_REQUEST, "Invalid 2FA code".to_string()));
    }

    let user_key = format!("users/{}.json", username);
    let mut user_json: serde_json::Value = match state
        .storage
        .get_object_bytes(&state.bucket, &user_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid JSON".to_string(),
            )
        })?,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "User not found".to_string(),
            ))
        }
    };

    if let Some(obj) = user_json.as_object_mut() {
        obj.insert("totp_enabled".to_string(), serde_json::json!(true));
        obj.insert("totp_secret".to_string(), serde_json::json!(payload.secret));
    }

    let user_bytes = serde_json::to_vec(&user_json)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JSON error".to_string()))?;
    state
        .storage
        .put_object(
            &state.bucket,
            &user_key,
            user_bytes,
            Some("application/json"),
        )
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to save user".to_string(),
            )
        })?;

    Ok(StatusCode::OK)
}

async fn disable_2fa(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<Disable2FARequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let user_key = format!("users/{}.json", username);
    let mut user_json: serde_json::Value = match state
        .storage
        .get_object_bytes(&state.bucket, &user_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid JSON".to_string(),
            )
        })?,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "User not found".to_string(),
            ))
        }
    };

    let totp_enabled = user_json
        .get("totp_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !totp_enabled {
        return Err((StatusCode::BAD_REQUEST, "2FA is not enabled".to_string()));
    }

    let totp_secret = user_json
        .get("totp_secret")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let secret = totp_rs::Secret::Encoded(totp_secret.to_string());
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid internal secret".to_string(),
            )
        })?,
        Some("DillShare".to_string()),
        username.clone(),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create TOTP".to_string(),
        )
    })?;

    if !totp.check_current(&payload.code).unwrap_or(false) {
        return Err((StatusCode::BAD_REQUEST, "Invalid 2FA code".to_string()));
    }

    if let Some(obj) = user_json.as_object_mut() {
        obj.insert("totp_enabled".to_string(), serde_json::json!(false));
        obj.remove("totp_secret");
    }

    let user_bytes = serde_json::to_vec(&user_json)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JSON error".to_string()))?;
    state
        .storage
        .put_object(
            &state.bucket,
            &user_key,
            user_bytes,
            Some("application/json"),
        )
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to save user".to_string(),
            )
        })?;

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_generated_share_object_names_are_accepted() {
        for valid in [
            "metadata.enc",
            "file_0.enc",
            "file_42.enc",
            "file_0.thumb.enc",
        ] {
            assert!(is_valid_upload_filename(valid), "{valid}");
        }
        for invalid in [
            "owner.txt",
            ".active",
            ".manifest.json",
            "file_00.enc",
            "file_-1.enc",
            "file_1/../../owner.txt",
            "file_1.thumb.enc/extra",
            "metadata.enc.bak",
        ] {
            assert!(!is_valid_upload_filename(invalid), "{invalid}");
        }
    }

    #[test]
    fn encrypted_sizes_match_the_browser_chunk_format() {
        assert_eq!(encrypted_file_size(0), Some(28));
        assert_eq!(encrypted_file_size(1), Some(29));
        assert_eq!(
            encrypted_file_size(ENCRYPTION_CHUNK_BYTES),
            Some(ENCRYPTION_CHUNK_BYTES + 28)
        );
        assert_eq!(
            encrypted_file_size(ENCRYPTION_CHUNK_BYTES + 1),
            Some(ENCRYPTION_CHUNK_BYTES + 1 + 56)
        );
        assert_eq!(encrypted_file_size(-1), None);
    }

    #[test]
    fn multipart_layout_matches_the_browser_pipeline() {
        let plaintext_size = 2 * ENCRYPTION_CHUNK_BYTES + 1;
        let parts = multipart_part_sizes(plaintext_size).unwrap();
        assert_eq!(parts, vec![2 * (ENCRYPTION_CHUNK_BYTES + 28), 29]);
        assert_eq!(
            parts.iter().sum::<i64>(),
            encrypted_file_size(plaintext_size).unwrap()
        );
    }

    #[test]
    fn sha256_checksum_must_decode_to_exactly_32_bytes() {
        let valid = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 31]);
        assert!(is_valid_sha256_checksum(&valid));
        assert!(!is_valid_sha256_checksum(&short));
        assert!(!is_valid_sha256_checksum("not base64"));
    }

    #[test]
    fn upload_ids_must_be_canonical_uuids() {
        let id = "550e8400-e29b-41d4-a716-446655440000".to_string();
        assert!(validate_upload_uuid(&id).is_ok());
        assert!(validate_upload_uuid(&id.to_uppercase()).is_err());
        assert!(validate_upload_uuid("../another-share").is_err());
    }

    #[test]
    fn encrypted_payload_hex_is_strict_and_bounded() {
        assert_eq!(decode_hex("00ff", 2).unwrap(), vec![0, 255]);
        assert!(decode_hex("0", 2).is_err());
        assert!(decode_hex("zz", 2).is_err());
        assert!(decode_hex("000000", 2).is_err());
    }

    #[test]
    fn signed_tokens_reject_tampering_and_expiry() {
        let secret = [7u8; 32];
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let token = generate_token("alice", &secret, 0, session_id);
        assert_eq!(
            verify_token_signature(&token, &secret),
            Some(("alice".to_string(), 0, session_id.to_string()))
        );
        assert!(verify_token_signature(&(token + "0"), &secret).is_none());
        let expired = generate_token("alice", &secret, 1, session_id);
        assert!(verify_token_signature(&expired, &secret).is_none());
    }

    #[tokio::test]
    async fn memory_storage_enforces_conditional_etags() {
        let storage = storage::Storage::Memory(std::sync::Arc::new(tokio::sync::Mutex::new(
            storage::MemoryBackend::default(),
        )));
        storage
            .put_object("test", "object", vec![1], None)
            .await
            .unwrap();
        let original_etag = storage
            .head_object_info("test", "object")
            .await
            .unwrap()
            .unwrap()
            .e_tag
            .unwrap();
        assert!(storage
            .put_object_if_match("test", "object", vec![2], None, &original_etag)
            .await
            .unwrap());
        assert!(!storage
            .put_object_if_match("test", "object", vec![3], None, &original_etag)
            .await
            .unwrap());
        assert_eq!(
            storage.get_object_bytes("test", "object").await.unwrap(),
            vec![2]
        );
    }

    #[tokio::test]
    async fn only_finish_authorization_can_resume_a_finishing_upload() {
        let storage = storage::Storage::Memory(std::sync::Arc::new(tokio::sync::Mutex::new(
            storage::MemoryBackend::default(),
        )));
        let rp_origin = webauthn_rs::prelude::Url::parse("http://localhost:3000").unwrap();
        let webauthn = std::sync::Arc::new(
            webauthn_rs::WebauthnBuilder::new("localhost", &rp_origin)
                .unwrap()
                .rp_name("DillShare")
                .build()
                .unwrap(),
        );
        let state = AppState {
            storage,
            bucket: "test".to_string(),
            jwt_secret: vec![],
            webauthn,
            presign_ttl: std::time::Duration::from_secs(60),
            share_expiry_secs: 3600,
            upload_session_max_secs: 3600,
            max_share_bytes: 1024 * 1024,
        };
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        write_active_upload_marker(
            &state,
            uuid,
            &ActiveUploadMarker {
                owner: "alice".to_string(),
                created_at: chrono::Utc::now().timestamp(),
                file_sizes: vec![1],
                status: "finishing".to_string(),
            },
        )
        .await
        .unwrap();

        assert!(authorize_active_upload(&state, uuid, "alice")
            .await
            .is_err());
        let marker = authorize_upload_marker(&state, uuid, "alice", Some("finishing"))
            .await
            .unwrap();
        assert_eq!(marker.status, "finishing");
    }
}
