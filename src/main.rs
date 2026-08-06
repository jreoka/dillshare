use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use base64::Engine;
use std::net::SocketAddr;
mod storage;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

async fn url_restriction_middleware(
    axum::extract::Extension(allowed_url): axum::extract::Extension<Option<String>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    if let Some(url) = allowed_url {
        let expected_host = url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');

        let host = req
            .headers()
            .get(axum::http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        let host_without_port = host.split(':').next().unwrap_or("");
        let expected_without_port = expected_host.split(':').next().unwrap_or("");

        if host_without_port != expected_without_port {
            tracing::warn!(
                "Forbidden: Host '{}' does not match allowed URL '{}'",
                host,
                url
            );
            return Err(axum::http::StatusCode::FORBIDDEN);
        }

        if let Some(origin) = req.headers().get(axum::http::header::ORIGIN) {
            if let Ok(origin_str) = origin.to_str() {
                if origin_str != url
                    && origin_str.trim_end_matches('/') != url.trim_end_matches('/')
                {
                    tracing::warn!(
                        "Forbidden: Origin '{}' does not match allowed URL '{}'",
                        origin_str,
                        url
                    );
                    return Err(axum::http::StatusCode::FORBIDDEN);
                }
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
}

#[tokio::main]
async fn main() {
    // Load .env file if it exists
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "s3_share=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load S3 Configuration
    let bucket = std::env::var("AWS_S3_BUCKET")
        .or_else(|_| std::env::var("S3_BUCKET"))
        .unwrap_or_else(|_| {
            if std::env::var("AWS_ACCESS_KEY_ID").is_err()
                || std::env::var("AWS_SECRET_ACCESS_KEY").is_err()
            {
                "local-testing-bucket".to_string()
            } else {
                panic!("AWS_S3_BUCKET or S3_BUCKET environment variable is required");
            }
        });

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

    let has_aws =
        std::env::var("AWS_ACCESS_KEY_ID").is_ok() || std::env::var("AWS_DEFAULT_REGION").is_ok();
    let storage = if has_aws {
        let s3_client = aws_sdk_s3::Client::from_conf(s3_config_builder.build());
        storage::Storage::S3(s3_client)
    } else {
        println!("WARNING: AWS envs not set. Running in memory testing mode.");
        storage::Storage::Memory(std::sync::Arc::new(tokio::sync::Mutex::new(
            storage::MemoryBackend::default(),
        )))
    };

    // Verify S3 Connection
    tracing::info!("Validating S3 connection to bucket '{}'...", bucket);
    match storage.list_objects(&bucket, None, Some(1)).await {
        Ok(_) => tracing::info!("S3 connection verified successfully."),
        Err(e) => {
            tracing::error!(
                "WARNING: S3 bucket validation failed! S3 calls may fail. Error: {:?}",
                e
            );
            tracing::error!("Please check your AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION).");
        }
    }

    // Get JWT secret from environment or load/generate in S3
    let jwt_secret = match std::env::var("JWT_SECRET") {
        Ok(secret_str) => secret_str.into_bytes(),
        Err(_) => {
            let secret_key = "config/jwt_secret.bin";
            match storage.get_object_bytes(&bucket, secret_key).await {
                Ok(bytes) => bytes,
                Err(_) => generate_and_save_jwt_secret(&storage, &bucket, secret_key).await,
            }
        }
    };

    let rp_id = std::env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let origin_str =
        std::env::var("RP_ORIGIN").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let rp_origin = webauthn_rs::prelude::Url::parse(&origin_str).expect("Invalid RP_ORIGIN URL");
    let builder =
        webauthn_rs::WebauthnBuilder::new(&rp_id, &rp_origin).expect("Invalid Webauthn builder");
    let builder = builder.rp_name("DillShare");
    let webauthn = std::sync::Arc::new(builder.build().expect("Invalid Webauthn config"));

    let state = AppState {
        storage: storage.clone(),
        bucket: bucket.clone(),
        jwt_secret,
        webauthn,
    };

    // Spawn background cleanup worker (runs every hour)
    tokio::spawn(run_cleanup_worker(storage, bucket));

    // Setup routes
    let app = Router::new()
        // API routes
        .route("/api/upload", post(upload_files))
        .route("/api/upload/init", post(upload_init))
        .route(
            "/api/upload/:uuid",
            post(upload_chunk_or_file).delete(upload_abort),
        )
        .route(
            "/api/upload/:uuid/multipart/init",
            post(upload_multipart_init),
        )
        .route(
            "/api/upload/:uuid/multipart/part",
            post(upload_multipart_part),
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
        // Admin routes
        .route("/api/admin/login", post(admin_login))
        .route("/api/admin/sessions", get(admin_get_sessions))
        .route(
            "/api/admin/sessions/:id",
            delete(admin_revoke_session).put(admin_rename_session),
        )
        .route("/api/admin/stats", get(admin_get_stats))
        .route("/api/admin/share/:uuid", delete(admin_delete_share))
        .route("/api/admin/user/:username", delete(admin_delete_user))
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
        .fallback(serve_index)
        // Router configurations
        .layer(DefaultBodyLimit::disable()) // Disable Axum's default 2MB multipart limit
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let allowed_url = std::env::var("URL").ok();

    let app = if let Some(url) = allowed_url.clone() {
        use axum::http::HeaderValue;
        use tower_http::cors::Any;
        if let Ok(origin) = url.parse::<HeaderValue>() {
            app.layer(
                CorsLayer::new()
                    .allow_origin(origin)
                    .allow_methods(Any)
                    .allow_headers(Any),
            )
        } else {
            app.layer(CorsLayer::permissive())
        }
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
    let index_key = format!(
        "passkey_index/{}",
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(passkey.cred_id())
    );
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
    let username_opt = payload.username.filter(|u| !u.trim().is_empty());

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

        let state_key = format!("users/{}/passkey_auth.json", username);
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
            "session_id": username
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
    let is_discoverable = payload
        .username
        .as_ref()
        .map_or(true, |u| u.trim().is_empty());

    let state_key = if is_discoverable {
        format!(
            "auth_sessions/{}.json",
            payload.session_id.unwrap_or_default()
        )
    } else {
        format!(
            "users/{}/passkey_auth.json",
            payload.username.as_ref().unwrap()
        )
    };

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
        (payload.username.unwrap(), auth_res)
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
    let passkeys_json = serde_json::to_vec(&passkeys).unwrap();
    let _ = state
        .storage
        .put_object(
            &state.bucket,
            &passkeys_key,
            passkeys_json,
            Some("application/json"),
        )
        .await;

    // Check 2FA before finalizing
    let user_key = format!("users/{}.json", username);
    let user_bytes = state
        .storage
        .get_object_bytes(&state.bucket, &user_key)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "User not found".to_string()))?;

    let user_json: serde_json::Value = serde_json::from_slice(&user_bytes)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid user data".to_string()))?;

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
            if let Ok(secret) = totp_rs::Secret::Encoded(totp_secret.to_string()).to_bytes()
            {
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
                    (StatusCode::INTERNAL_SERVER_ERROR, "2FA Error".to_string())
                })?;

                if !totp.check_current(code).unwrap_or(false) {
                    return Err((StatusCode::FORBIDDEN, "INVALID_2FA".to_string()));
                }
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
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()))
        .unwrap_or("Unknown")
        .to_string();

    sessions.push(UserSession {
        id: session_id,
        created_at: chrono::Utc::now().timestamp(),
        expires_at: expiry,
        ip,
        user_agent,
        name: None,
    });

    let sessions_json = serde_json::to_vec(&sessions).unwrap();
    let _ = state
        .storage
        .put_object(
            &state.bucket,
            &sessions_key,
            sessions_json,
            Some("application/json"),
        )
        .await;

    let pfp_enc = fetch_user_pfp_enc(&state, &username).await;

    Ok(Json(serde_json::json!({
        "success": true,
        "token": token,
        "username": username,
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
    passkeys.retain(|pk| {
        let pk_id = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(pk.cred_id());
        pk_id != id
    });

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

    let meta_key = format!("users/{}/passkeys_meta.json", username);
    let mut meta_map: std::collections::HashMap<String, PasskeyMeta> = match state
        .storage
        .get_object_bytes(&state.bucket, &meta_key)
        .await
    {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => std::collections::HashMap::new(),
    };

    meta_map.insert(id, PasskeyMeta { name: payload.name });

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

// Serve embedded single page app index.html
async fn serve_index() -> impl IntoResponse {
    Html(include_str!("index.html"))
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

// Multipart file uploader - requires authentication
async fn upload_files(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let uuid = uuid::Uuid::new_v4().to_string();

    let result: Result<axum::Json<serde_json::Value>, (StatusCode, String)> =
        upload_files_inner(&state, &username, &uuid, multipart).await;

    match result {
        Ok(json) => Ok(json),
        Err(err) => {
            // Upload failed or aborted — remove anything already written for this share.
            let prefix = format!("uploads/{}/", uuid);
            tracing::warn!(
                "Upload {} failed ({:?}); cleaning up S3 prefix '{}'",
                uuid,
                err,
                prefix
            );
            if let Err(cleanup_err) = delete_s3_prefix(&state.storage, &state.bucket, &prefix).await
            {
                tracing::error!(
                    "Failed to clean up aborted upload {}: {:?}",
                    uuid,
                    cleanup_err
                );
            }
            Err(err)
        }
    }
}

/// Validate a client-supplied file name before it becomes part of an S3 key.
/// Rejects path separators, traversal, hidden/system filenames and reserved
/// internal names so uploads can never clobber share metadata objects.
fn is_valid_upload_filename(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.starts_with('.')
        && name != "owner.txt"
        && name != ".active"
}

async fn upload_files_inner(
    state: &AppState,
    username: &str,
    uuid: &str,
    mut multipart: Multipart,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let mut uploaded_files = Vec::new();
    let mut total_size = 0;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let file_path = match field.file_name() {
            Some(name) => name.to_string(),
            None => continue,
        };

        if file_path.trim().is_empty() {
            continue;
        }

        if !is_valid_upload_filename(&file_path) {
            tracing::warn!(
                "Rejecting upload with invalid file name '{:?}' for share {}",
                file_path,
                uuid
            );
            return Err((
                StatusCode::BAD_REQUEST,
                "Invalid file name (must not contain path separators or reserved names)"
                    .to_string(),
            ));
        }

        let content_type = mime_guess::from_path(&file_path)
            .first_or_octet_stream()
            .to_string();

        let bytes = field
            .bytes()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        total_size += bytes.len() as i64;

        let key = format!("uploads/{}/{}", uuid, file_path);
        tracing::info!("Uploading {} to S3 bucket '{}'...", file_path, state.bucket);

        state
            .storage
            .put_object(&state.bucket, &key, bytes.to_vec(), Some(&content_type))
            .await
            .map_err(|e| {
                tracing::error!("S3 PutObject error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to upload to S3: {:?}", e),
                )
            })?;

        uploaded_files.push(file_path);
    }

    if uploaded_files.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No files uploaded".to_string()));
    }

    // Write owner record
    let owner_key = format!("uploads/{}/owner.txt", uuid);
    state
        .storage
        .put_object(
            &state.bucket,
            &owner_key,
            username.as_bytes().to_vec().to_vec(),
            Some("text/plain"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save owner: {:?}", e),
            )
        })?;

    // Actual user files count (excluding metadata.enc)
    let files_count = uploaded_files
        .iter()
        .filter(|f| *f != "metadata.enc")
        .count();

    // Update user's public shares index in S3
    let public_shares_key = format!("users/{}/public_shares.json", username);
    let mut shares = match state
        .storage
        .get_object_bytes(&state.bucket, &public_shares_key)
        .await
    {
        Ok(bytes) => {
            if true {
                serde_json::from_slice::<Vec<serde_json::Value>>(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    shares.push(serde_json::json!({
        "uuid": uuid,
        "files_count": files_count,
        "total_size": total_size,
        "created_at": chrono::Utc::now().to_rfc3339()
    }));

    let shares_bytes = serde_json::to_vec(&shares)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .storage
        .put_object(
            &state.bucket,
            &public_shares_key,
            shares_bytes.into(),
            Some("application/json"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save public shares list: {:?}", e),
            )
        })?;

    Ok(axum::Json(serde_json::json!({
        "uuid": uuid,
        "files": uploaded_files
    })))
}

async fn upload_init(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let uuid = uuid::Uuid::new_v4().to_string();

    // Write initial active heartbeat marker
    let active_key = format!("uploads/{}/.active", uuid);
    let _ = state
        .storage
        .put_object(
            &state.bucket,
            &active_key,
            b"active".to_vec().to_vec(),
            Some("text/plain"),
        )
        .await;

    Ok(axum::Json(serde_json::json!({
        "uuid": uuid
    })))
}

async fn upload_ping(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let active_key = format!("uploads/{}/.active", uuid);
    state
        .storage
        .put_object(
            &state.bucket,
            &active_key,
            b"active".to_vec().to_vec(),
            Some("text/plain"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update heartbeat: {:?}", e),
            )
        })?;

    Ok(axum::Json(serde_json::json!({ "status": "ok" })))
}

async fn upload_chunk_or_file(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let mut uploaded_files = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let file_path = match field.file_name() {
            Some(name) => name.to_string(),
            None => continue,
        };

        if file_path.trim().is_empty() {
            continue;
        }

        if !is_valid_upload_filename(&file_path) {
            tracing::warn!(
                "Rejecting upload with invalid file name '{:?}' for share {}",
                file_path,
                uuid
            );
            return Err((
                StatusCode::BAD_REQUEST,
                "Invalid file name (must not contain path separators or reserved names)"
                    .to_string(),
            ));
        }

        let content_type = mime_guess::from_path(&file_path)
            .first_or_octet_stream()
            .to_string();

        let bytes = field
            .bytes()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let key = format!("uploads/{}/{}", uuid, file_path);
        tracing::info!("Uploading {} to S3 bucket '{}'...", file_path, state.bucket);

        state
            .storage
            .put_object(&state.bucket, &key, bytes.to_vec(), Some(&content_type))
            .await
            .map_err(|e| {
                tracing::error!("S3 PutObject error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to upload to S3: {:?}", e),
                )
            })?;

        uploaded_files.push(file_path);
    }

    // Refresh active heartbeat timestamp on chunk/file activity asynchronously
    let active_key = format!("uploads/{}/.active", uuid);
    tokio::spawn(async move {
        let _ = state
            .storage
            .put_object(
                &state.bucket,
                &active_key,
                b"active".to_vec().to_vec(),
                Some("text/plain"),
            )
            .await;
    });

    Ok(axum::Json(serde_json::json!({
        "status": "ok",
        "uploaded": uploaded_files
    })))
}

#[derive(serde::Deserialize)]
struct UploadFinishReq {
    files_count: Option<usize>,
    total_size: Option<i64>,
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

    // Write owner record
    let owner_key = format!("uploads/{}/owner.txt", uuid);
    state
        .storage
        .put_object(
            &state.bucket,
            &owner_key,
            username.as_bytes().to_vec().to_vec(),
            Some("text/plain"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save owner: {:?}", e),
            )
        })?;

    // List files under uploads/{uuid}/ to count and check uploaded files
    let prefix = format!("uploads/{}/", uuid);
    let mut uploaded_files = Vec::new();
    let mut s3_total_size: i64 = 0;

    let list_res = state
        .storage
        .list_objects(&state.bucket, Some(&prefix), None)
        .await;

    if let Ok(out) = list_res {
        if true {
            let objects = out;
            for obj in objects {
                if true {
                    let k = &obj.key;
                    let rel_path = k.strip_prefix(&prefix).unwrap_or(&k).to_string();
                    if rel_path != "owner.txt" && rel_path != ".active" {
                        uploaded_files.push(rel_path.clone());
                    }
                    if rel_path != "owner.txt"
                        && rel_path != ".active"
                        && rel_path != "metadata.enc"
                        && !rel_path.ends_with(".thumb.enc")
                    {
                        s3_total_size += obj.size;
                    }
                }
            }
        }
    }

    let files_count = payload.files_count.unwrap_or_else(|| {
        uploaded_files
            .iter()
            .filter(|f| *f != "metadata.enc" && !f.ends_with(".thumb.enc"))
            .count()
    });
    let total_size = payload.total_size.unwrap_or(s3_total_size);

    // Update user's public shares index in S3
    let public_shares_key = format!("users/{}/public_shares.json", username);
    let mut shares = match state
        .storage
        .get_object_bytes(&state.bucket, &public_shares_key)
        .await
    {
        Ok(bytes) => {
            if true {
                serde_json::from_slice::<Vec<serde_json::Value>>(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    shares.push(serde_json::json!({
        "uuid": uuid,
        "files_count": files_count,
        "total_size": total_size,
        "created_at": chrono::Utc::now().to_rfc3339()
    }));

    let shares_bytes = serde_json::to_vec(&shares)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .storage
        .put_object(
            &state.bucket,
            &public_shares_key,
            shares_bytes.into(),
            Some("application/json"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save public shares list: {:?}", e),
            )
        })?;

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
    let (_username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let prefix = format!("uploads/{}/", uuid);
    tracing::info!(
        "Aborting upload session {}; cleaning up S3 prefix '{}'",
        uuid,
        prefix
    );
    delete_s3_prefix(&state.storage, &state.bucket, &prefix).await?;

    Ok(axum::Json(serde_json::json!({ "status": "aborted" })))
}

#[derive(serde::Deserialize)]
struct MultipartInitReq {
    file_name: String,
}

async fn upload_multipart_init(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<MultipartInitReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    if !is_valid_upload_filename(&payload.file_name) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid file name (must not contain path separators or reserved names)"
                .to_string(),
        ));
    }

    let key = format!("uploads/{}/{}", uuid, payload.file_name);
    let content_type = mime_guess::from_path(&payload.file_name)
        .first_or_octet_stream()
        .to_string();

    let upload_id = state
        .storage
        .create_multipart_upload(&state.bucket, &key, Some(&content_type))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create S3 multipart upload: {:?}", e),
            )
        })?;

    Ok(axum::Json(serde_json::json!({ "upload_id": upload_id })))
}

#[derive(serde::Deserialize)]
struct MultipartPartQuery {
    upload_id: String,
    part_number: i32,
    file_name: String,
}

async fn upload_multipart_part(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    axum::extract::Query(query): axum::extract::Query<MultipartPartQuery>,
    headers: axum::http::HeaderMap,
    bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    if !is_valid_upload_filename(&query.file_name) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid file name (must not contain path separators or reserved names)"
                .to_string(),
        ));
    }
    if !(1..=10_000).contains(&query.part_number) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Part number must be between 1 and 10000".to_string(),
        ));
    }

    let key = format!("uploads/{}/{}", uuid, query.file_name);

    let e_tag = state
        .storage
        .upload_part(
            &state.bucket,
            &key,
            &query.upload_id,
            query.part_number,
            bytes.to_vec(),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to upload part: {:?}", e),
            )
        })?;

    // Refresh active heartbeat timestamp on part activity asynchronously
    let active_key = format!("uploads/{}/.active", uuid);
    tokio::spawn(async move {
        let _ = state
            .storage
            .put_object(
                &state.bucket,
                &active_key,
                b"active".to_vec().to_vec(),
                Some("text/plain"),
            )
            .await;
    });

    Ok(axum::Json(serde_json::json!({
        "part_number": query.part_number,
        "e_tag": e_tag
    })))
}

#[derive(serde::Deserialize)]
struct CompletedPartReq {
    part_number: i32,
    e_tag: String,
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
    let (_username, _) = verify_session(&token, &state).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired session".to_string(),
        )
    })?;

    let key = format!("uploads/{}/{}", uuid, payload.file_name);

    let mut completed_parts = Vec::new();
    for p in payload.parts {
        let completed_part = crate::storage::CompletedPart {
            part_number: p.part_number,
            e_tag: p.e_tag,
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

    Ok(axum::Json(serde_json::json!({ "status": "ok" })))
}

// Get details of a single share UUID
async fn get_share(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let prefix = format!("uploads/{}/", uuid);

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
    let mut latest_upload_time = chrono::Utc::now();
    let mut has_objects = false;

    let objects = state
        .storage
        .list_objects(&state.bucket, Some(&prefix), None)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    for object in objects {
        let key = object.key;
        let size = object.size;
        let last_modified_secs = object.last_modified_secs;

        let file_name = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
        if file_name == "owner.txt" || file_name == ".active" {
            continue;
        }

        let upload_time = chrono::DateTime::<chrono::Utc>::from_timestamp(last_modified_secs, 0)
            .unwrap_or_else(|| chrono::Utc::now());

        if !has_objects {
            latest_upload_time = upload_time;
            has_objects = true;
        } else if upload_time > latest_upload_time {
            latest_upload_time = upload_time;
        }

        // Hide internal artifacts (encrypted manifest, thumbnails) from the
        // public file listing; viewers read the decrypted manifest instead.
        if file_name == "metadata.enc" || file_name.ends_with(".thumb.enc") {
            continue;
        }

        files.push(ShareFile {
            name: file_name,
            size,
        });
    }

    if !has_objects {
        return Err((
            StatusCode::NOT_FOUND,
            "Share not found or expired".to_string(),
        ));
    }

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

    let owner_pfp = None;

    let expires_at = latest_upload_time + chrono::Duration::days(90);

    Ok(axum::Json(ShareDetails {
        uuid,
        upload_time: latest_upload_time,
        expires_at,
        files,
        owner,
        owner_pfp,
    }))
}

// Download/stream a file from S3 share
// Supports HTTP Range requests so that a Service Worker can fetch individual
// encrypted chunks on demand for streaming preview of large media files.
async fn download_file(
    State(state): State<AppState>,
    Path((uuid, filename)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let key = format!("uploads/{}/{}", uuid, filename);

    let raw_range_header = headers
        .get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok().map(|s| s.to_string()));

    let res = match state.storage.get_object(&state.bucket, &key, raw_range_header).await {
        Ok(output) => output,
        Err(e) => {
            let (status, msg) = match &e {
                storage::StorageError::NotFound(_) => {
                    (StatusCode::NOT_FOUND, "File not found")
                }
                storage::StorageError::InvalidRange(_) => {
                    (StatusCode::RANGE_NOT_SATISFIABLE, "Requested range not satisfiable")
                }
                storage::StorageError::Other(_) => {
                    tracing::error!("S3 GetObject error: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                }
            };
            return Response::builder()
                .status(status)
                .header(axum::http::header::ACCEPT_RANGES, "bytes")
                .body(Body::from(msg))
                .unwrap();
        }
    };

    let body = res.body;

    let status = if res.content_range.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut builder = Response::builder().status(status);

    if let Some(ref content_type) = res.content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    } else {
        let guessed = mime_guess::from_path(&filename)
            .first_or_octet_stream()
            .to_string();
        builder = builder.header(CONTENT_TYPE, guessed);
    }

    if let Some(content_length) = res.content_length {
        builder = builder.header(CONTENT_LENGTH, content_length);
    }

    if let Some(content_range) = res.content_range {
        builder = builder.header(
            axum::http::header::CONTENT_RANGE,
            content_range,
        );
    }

    // Advertise range support so media engines will issue range requests.
    builder = builder.header(axum::http::header::ACCEPT_RANGES, "bytes");

    let encoded_filename =
        percent_encoding::utf8_percent_encode(&filename, percent_encoding::NON_ALPHANUMERIC)
            .to_string();

    builder = builder.header(
        CONTENT_DISPOSITION,
        format!("inline; filename*=UTF-8''{}", encoded_filename),
    );

    builder.body(body).unwrap()
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

    // Check ownership
    let owner_key = format!("uploads/{}/owner.txt", uuid);
    let owner_res = state
        .storage
        .get_object_bytes(&state.bucket, &owner_key)
        .await;

    let owner = match owner_res {
        Ok(bytes) => {
            if true {
                String::from_utf8(bytes.to_vec())
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            } else {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Share has no valid owner recorded".to_string(),
                ));
            }
        }
        Err(_) => {
            return Err((StatusCode::FORBIDDEN, "Cannot verify ownership".to_string()));
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
    if let Ok(bytes) = storage.get_object_bytes(bucket, &public_shares_key).await {
        if let Ok(mut shares) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
            shares.retain(|s| s.get("uuid").and_then(|u| u.as_str()) != Some(uuid));
            if let Ok(shares_bytes) = serde_json::to_vec(&shares) {
                let _ = storage
                    .put_object(
                        bucket,
                        &public_shares_key,
                        shares_bytes,
                        Some("application/json"),
                    )
                    .await;
            }
        }
    }
}

// Background cleanup worker thread - deletes S3 objects older than 90 days or abandoned partial uploads older than 1 hour
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
    latest_modified_secs: i64,
    keys: Vec<String>,
}

async fn perform_cleanup(
    storage: &storage::Storage,
    bucket: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let share_expiry_days = std::env::var("DILLSHARE_EXPIRE_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(90);
    let share_expire_limit = share_expiry_days * 24 * 60 * 60;

    let partial_timeout_hours = std::env::var("DILLSHARE_PARTIAL_TIMEOUT_HOURS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(12); // Default to 12 hours for incomplete / cancelled / abandoned uploads
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
            latest_modified_secs: 0,
            keys: Vec::new(),
        });

        if rel.ends_with("/owner.txt") || rel == "owner.txt" {
            entry.has_owner = true;
        }
        if mod_secs > entry.latest_modified_secs {
            entry.latest_modified_secs = mod_secs;
        }
        entry.keys.push(key.to_string());
    }

    let mut keys_to_delete = Vec::new();
    let mut expired_share_uuids = Vec::new();

    for (uuid, group) in groups {
        let age = now - group.latest_modified_secs;
        if group.has_owner {
            if age > share_expire_limit {
                tracing::info!(
                    "Completed share '{}' is older than {} days (age: {}s). Marking for deletion.",
                    uuid,
                    share_expiry_days,
                    age
                );
                keys_to_delete.extend(group.keys);
                expired_share_uuids.push(uuid);
            }
        } else {
            if age > partial_upload_limit {
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
    if let Ok(sessions) = storage.list_objects(bucket, Some("auth_sessions/"), None).await {
        for session in sessions {
            if now - session.last_modified_secs > partial_upload_limit {
                keys_to_delete.push(session.key);
            }
        }
    }

    // Cleanup old user passkey states
    if let Ok(users) = storage.list_objects(bucket, Some("users/"), None).await {
        for object in users {
            if object.key.ends_with("/passkey_reg.json") || object.key.ends_with("/passkey_auth.json") {
                if now - object.last_modified_secs > partial_upload_limit {
                    keys_to_delete.push(object.key);
                }
            }
        }
    }

    // Cleanup orphaned passkey indexes
    if let Ok(indexes) = storage.list_objects(bucket, Some("passkey_index/"), None).await {
        for index in indexes {
            let cred_id_b64 = index.key.strip_prefix("passkey_index/").unwrap_or(&index.key);
            let mut keep = false;
            if let Ok(bytes) = storage.get_object_bytes(bucket, &index.key).await {
                if let Ok(username) = String::from_utf8(bytes.to_vec()) {
                    let passkeys_key = format!("users/{}/passkeys.json", username.trim());
                    if let Ok(pk_bytes) = storage.get_object_bytes(bucket, &passkeys_key).await {
                        if let Ok(passkeys) = serde_json::from_slice::<Vec<webauthn_rs::prelude::Passkey>>(&pk_bytes) {
                            use base64::Engine;
                            keep = passkeys.iter().any(|pk| {
                                base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(pk.cred_id()) == cred_id_b64
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

async fn register_user(
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<AuthRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let username = payload.username.trim();
    if username.is_empty() || username.len() < 3 || username.len() > 30 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username must be between 3 and 30 characters".to_string(),
        ));
    }

    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username can only contain letters, numbers, dashes, and underscores".to_string(),
        ));
    }

    let user_key = format!("users/{}.json", username);

    // Check if user already exists
    let user_exists = state
        .storage
        .head_object(&state.bucket, &user_key)
        .await
        .unwrap_or(false);

    if user_exists {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username is already taken".to_string(),
        ));
    }

    // Hash the auth_key with a server salt
    let mut hasher = Sha256::new();
    hasher.update(payload.auth_key.as_bytes());
    hasher.update(b"server-salt-dill-share");
    let password_hash = format!("{:02x}", hasher.finalize());

    let user_data = serde_json::json!({
        "password_hash": password_hash
    });
    let user_bytes = serde_json::to_vec(&user_data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Save to S3
    state
        .storage
        .put_object(
            &state.bucket,
            &user_key,
            user_bytes.into(),
            Some("application/json"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save user: {:?}", e),
            )
        })?;

    Ok(StatusCode::OK)
}

async fn login_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<AuthRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let username = payload.username.trim();
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

    if computed_hash != stored_hash {
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
            if let Ok(secret) = totp_rs::Secret::Encoded(totp_secret.to_string()).to_bytes() {
                let totp = totp_rs::TOTP::new(
                    totp_rs::Algorithm::SHA1,
                    6,
                    1,
                    30,
                    secret,
                    Some("DillShare".to_string()),
                    username.to_string(),
                )
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "2FA Error".to_string()))?;

                if !totp.check_current(code).unwrap_or(false) {
                    return Err((StatusCode::FORBIDDEN, "INVALID_2FA".to_string()));
                }
            }
        } else {
            return Err((StatusCode::FORBIDDEN, "2FA_REQUIRED".to_string()));
        }
    }

    // Generate token with a unique session id (sessions never expire)
    let session_id = uuid::Uuid::new_v4().to_string();
    let expiry = 0;
    let token = generate_token(username, &state.jwt_secret, expiry, &session_id);

    // Extract user agent and IP
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()))
        .unwrap_or("Unknown")
        .to_string();

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
        Ok(bytes) => {
            if true {
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    sessions.push(new_session);

    if let Ok(session_bytes) = serde_json::to_vec(&sessions) {
        let _ = state
            .storage
            .put_object(
                &state.bucket,
                &sessions_key,
                session_bytes.into(),
                Some("application/json"),
            )
            .await;
    }

    let pfp_enc = fetch_user_pfp_enc(&state, username).await;

    Ok(axum::Json(serde_json::json!({
        "token": token,
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

    // Decode hex string back to bytes
    let mut bytes = Vec::new();
    let shares_hex = payload.shares_enc.trim();
    for i in (0..shares_hex.len()).step_by(2) {
        if i + 2 > shares_hex.len() {
            break;
        }
        let byte_str = &shares_hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Invalid encrypted payload hex encoding".to_string(),
            )
        })?;
        bytes.push(byte);
    }

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

    if !auth_str.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Authorization scheme must be Bearer".to_string(),
        ));
    }

    Ok(auth_str[7..].to_string())
}

type HmacSha256 = Hmac<Sha256>;

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

    let mut username_bytes = Vec::new();
    for i in (0..username_hex.len()).step_by(2) {
        if i + 2 > username_hex.len() {
            break;
        }
        let byte_str = &username_hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).ok()?;
        username_bytes.push(byte);
    }
    let username = String::from_utf8(username_bytes).ok()?;

    let payload = format!("{}:{}:{}", username, expiry_timestamp, session_id);
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(payload.as_bytes());
    let expected_sig = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    if expected_sig == signature {
        Some((username, expiry_timestamp, session_id.to_string()))
    } else {
        None
    }
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
    verify_admin(&headers, &state).await?;

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
                users_list.push(username);
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
                if true {
                    serde_json::from_slice::<Vec<serde_json::Value>>(&bytes).unwrap_or_default()
                } else {
                    Vec::new()
                }
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
            .map(|s| s.get("total_size").and_then(|sz| sz.as_i64()).unwrap_or(0))
            .sum();

        stats.push(serde_json::json!({
            "username": username,
            "total_size": total_size,
            "shares": shares,
            "has_2fa": totp_enabled
        }));
    }

    Ok(axum::Json(stats))
}

async fn admin_delete_share(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let owner_key = format!("uploads/{}/owner.txt", uuid);
    let owner_res = state
        .storage
        .get_object_bytes(&state.bucket, &owner_key)
        .await;

    let owner = match owner_res {
        Ok(bytes) => {
            if true {
                String::from_utf8(bytes.to_vec())
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            } else {
                String::new()
            }
        }
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
                if true {
                    let key = &object;
                    if key.key.ends_with("/public_shares.json") {
                        if let Some(user_part) = key
                            .key
                            .strip_prefix("users/")
                            .and_then(|k| k.strip_suffix("/public_shares.json"))
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
    }

    Ok(StatusCode::OK)
}

async fn admin_delete_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let username = username.trim();
    if username.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Username is empty".to_string()));
    }

    let public_shares_key = format!("users/{}/public_shares.json", username);
    if let Ok(bytes) = state
        .storage
        .get_object_bytes(&state.bucket, &public_shares_key)
        .await
    {
        if true {
            if let Ok(shares) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
                for share in shares {
                    if let Some(uuid) = share.get("uuid").and_then(|u| u.as_str()) {
                        let _ = delete_share_objects(&state.storage, &state.bucket, uuid).await;
                    }
                }
            }
        }
    }

    let user_profile_key = format!("users/{}.json", username);
    let user_folder_prefix = format!("users/{}/", username);

    let _ = state
        .storage
        .delete_object(&state.bucket, &user_profile_key)
        .await;
    let _ = delete_s3_prefix(&state.storage, &state.bucket, &user_folder_prefix).await;

    Ok(StatusCode::OK)
}

async fn verify_admin_session(token: &str, state: &AppState) -> bool {
    let (username, _expiry, session_id) = match verify_token_signature(token, &state.jwt_secret) {
        Some(val) => val,
        None => return false,
    };

    if username != "admin" {
        return false;
    }

    let sessions_key = "admin/sessions.json";
    let res = state
        .storage
        .get_object_bytes(&state.bucket, sessions_key)
        .await;

    match res {
        Ok(bytes) => {
            if true {
                let sessions: Vec<UserSession> = match serde_json::from_slice(&bytes) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                sessions.iter().any(|s| s.id == session_id)
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

async fn verify_admin(
    headers: &axum::http::HeaderMap,
    state: &AppState,
) -> Result<(), (StatusCode, String)> {
    let admin_token_env = std::env::var("ADMIN_TOKEN")
        .map_err(|_| (StatusCode::FORBIDDEN, "Admin panel is disabled".to_string()))?;

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Authorization header missing".to_string(),
            )
        })?;

    let auth_str = auth_header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid authorization characters".to_string(),
        )
    })?;

    if !auth_str.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Authorization scheme must be Bearer".to_string(),
        ));
    }

    let token = &auth_str[7..];
    if token == admin_token_env {
        return Ok(());
    }

    if verify_admin_session(token, state).await {
        return Ok(());
    }

    Err((StatusCode::FORBIDDEN, "Invalid admin token".to_string()))
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
        Ok(bytes) => {
            if true {
                let vec = bytes;
                vec.iter().map(|b| format!("{:02x}", b)).collect::<String>()
            } else {
                String::new()
            }
        }
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
        if true {
            if let Ok(user_json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                totp_enabled = user_json
                    .get("totp_enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            }
        }
    }

    Ok(axum::Json(serde_json::json!({
        "username": username,
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
        if true {
            if let Ok(mut user_json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(obj) = user_json.as_object_mut() {
                    if obj.remove("pfp").is_some() {
                        if let Ok(user_bytes) = serde_json::to_vec(&user_json) {
                            let _ = state
                                .storage
                                .put_object(
                                    &state.bucket,
                                    &user_key,
                                    user_bytes.into(),
                                    Some("application/json"),
                                )
                                .await;
                        }
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
        let mut bytes = Vec::new();
        let hex_str = hex_data.trim();
        for i in (0..hex_str.len()).step_by(2) {
            if i + 2 > hex_str.len() {
                break;
            }
            let byte_str = &hex_str[i..i + 2];
            let byte = u8::from_str_radix(byte_str, 16).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "Invalid encrypted payload hex encoding".to_string(),
                )
            })?;
            bytes.push(byte);
        }

        if bytes.len() > 12_000_000 {
            return Err((
                StatusCode::BAD_REQUEST,
                "Profile picture too large".to_string(),
            ));
        }

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

    if computed_hash != stored_hash {
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
            user_bytes.into(),
            Some("application/json"),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update profile: {:?}", e),
            )
        })?;

    let mut enc_bytes = Vec::new();
    let shares_hex = payload.new_shares_enc.trim();
    for i in (0..shares_hex.len()).step_by(2) {
        if i + 2 > shares_hex.len() {
            break;
        }
        let byte_str = &shares_hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Invalid encrypted payload hex encoding".to_string(),
            )
        })?;
        enc_bytes.push(byte);
    }

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
            let mut bytes = Vec::new();
            let hex_str = new_pfp.trim();
            for i in (0..hex_str.len()).step_by(2) {
                if i + 2 > hex_str.len() {
                    break;
                }
                let byte_str = &hex_str[i..i + 2];
                if let Ok(byte) = u8::from_str_radix(byte_str, 16) {
                    bytes.push(byte);
                }
            }
            let _ = state
                .storage
                .put_object(
                    &state.bucket,
                    &pfp_key,
                    bytes,
                    Some("application/octet-stream"),
                )
                .await;
        }
    }

    // Revoke all OTHER sessions of this user upon password change (forces relogin on other devices)
    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, &sessions_key)
        .await
    {
        Ok(bytes) => {
            if true {
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    sessions.retain(|s| s.id == current_session_id);

    if let Ok(session_bytes) = serde_json::to_vec(&sessions) {
        let _ = state
            .storage
            .put_object(
                &state.bucket,
                &sessions_key,
                session_bytes.into(),
                Some("application/json"),
            )
            .await;
    }

    Ok(StatusCode::OK)
}

async fn user_delete_account(
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

    let public_shares_key = format!("users/{}/public_shares.json", username);
    if let Ok(bytes) = state
        .storage
        .get_object_bytes(&state.bucket, &public_shares_key)
        .await
    {
        if true {
            if let Ok(shares) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
                for share in shares {
                    if let Some(uuid) = share.get("uuid").and_then(|u| u.as_str()) {
                        let _ = delete_share_objects(&state.storage, &state.bucket, uuid).await;
                    }
                }
            }
        }
    }

    let user_profile_key = format!("users/{}.json", username);
    let user_folder_prefix = format!("users/{}/", username);

    let _ = state
        .storage
        .delete_object(&state.bucket, &user_profile_key)
        .await;
    let _ = delete_s3_prefix(&state.storage, &state.bucket, &user_folder_prefix).await;

    Ok(StatusCode::OK)
}

async fn generate_and_save_jwt_secret(
    storage: &storage::Storage,
    bucket: &str,
    key: &str,
) -> Vec<u8> {
    let mut secret = [0u8; 32];
    use rand::Rng;
    rand::rng().fill_bytes(&mut secret);

    let _ = storage.put_object(bucket, key, secret.to_vec(), None).await;

    secret.to_vec()
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
        Ok(bytes) => {
            if true {
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
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
        Ok(bytes) => {
            if true {
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
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
                session_bytes.into(),
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
        Ok(bytes) => {
            if true {
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
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
                session_bytes.into(),
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
        Ok(bytes) => {
            if true {
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
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
        Ok(bytes) => {
            if true {
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
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
                session_bytes.into(),
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

async fn admin_login(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let admin_token_env = std::env::var("ADMIN_TOKEN")
        .map_err(|_| (StatusCode::FORBIDDEN, "Admin panel is disabled".to_string()))?;

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Authorization header missing".to_string(),
            )
        })?;

    let auth_str = auth_header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid authorization characters".to_string(),
        )
    })?;

    if !auth_str.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Authorization scheme must be Bearer".to_string(),
        ));
    }

    let token = &auth_str[7..];
    if token != admin_token_env {
        return Err((StatusCode::FORBIDDEN, "Invalid admin token".to_string()));
    }

    let expiry = 0;
    let session_id = uuid::Uuid::new_v4().to_string();
    let session_token = generate_token("admin", &state.jwt_secret, expiry, &session_id);

    let ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let new_session = UserSession {
        id: session_id,
        created_at: chrono::Utc::now().timestamp(),
        user_agent,
        ip,
        expires_at: expiry,
        name: None,
    };

    let sessions_key = "admin/sessions.json";
    let mut sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, sessions_key)
        .await
    {
        Ok(bytes) => {
            if true {
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    sessions.push(new_session);

    if let Ok(session_bytes) = serde_json::to_vec(&sessions) {
        state
            .storage
            .put_object(
                &state.bucket,
                sessions_key,
                session_bytes.into(),
                Some("application/json"),
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to save admin session: {:?}", e),
                )
            })?;
    }

    Ok(axum::Json(serde_json::json!({ "token": session_token })))
}

async fn admin_get_sessions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let sessions_key = "admin/sessions.json";
    let sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, sessions_key)
        .await
    {
        Ok(bytes) => {
            if true {
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    let mut response_sessions = Vec::new();

    let current_session_id =
        if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    verify_token_signature(token, &state.jwt_secret)
                        .map(|(_, _, session_id)| session_id)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

    for s in sessions {
        let is_current = current_session_id.as_ref() == Some(&s.id);
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

async fn admin_revoke_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let sessions_key = "admin/sessions.json";
    let mut sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, sessions_key)
        .await
    {
        Ok(bytes) => {
            if true {
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
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
                sessions_key,
                session_bytes.into(),
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

async fn admin_rename_session(
    State(state): State<AppState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<RenameSessionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let sessions_key = "admin/sessions.json";
    let mut sessions: Vec<UserSession> = match state
        .storage
        .get_object_bytes(&state.bucket, sessions_key)
        .await
    {
        Ok(bytes) => {
            if true {
                serde_json::from_slice(&bytes).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
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
                sessions_key,
                session_bytes.into(),
                Some("application/json"),
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to update admin session: {:?}", e),
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
        secret.to_bytes().unwrap(),
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
            user_bytes.into(),
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
            user_bytes.into(),
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
