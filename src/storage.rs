use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub const ENCRYPTED_STORAGE_MAGIC: &[u8] = b"DSENC1\0";
const NONCE_LEN: usize = 12;

#[derive(Clone)]
pub struct StorageCipher {
    cipher: Aes256Gcm,
}

impl StorageCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
        }
    }

    #[allow(dead_code)]
    pub fn from_slice(key_bytes: &[u8]) -> Result<Self, String> {
        if key_bytes.len() != 32 {
            return Err("Storage encryption key must be exactly 32 bytes".to_string());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(key_bytes);
        Ok(Self::new(&key))
    }

    /// Derive a 32-byte key from secret bytes using HMAC-SHA256
    pub fn derive_from_secret(secret: &[u8]) -> Self {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(b"dillshare-storage-encryption-v1")
            .expect("HMAC can take key of any size");
        mac.update(secret);
        let result = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Self::new(&key)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        use rand::Rng;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Storage encryption failed: {e}"))?;

        let mut out = Vec::with_capacity(ENCRYPTED_STORAGE_MAGIC.len() + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(ENCRYPTED_STORAGE_MAGIC);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if !data.starts_with(ENCRYPTED_STORAGE_MAGIC) {
            // Unencrypted / legacy plaintext - transparent backward compatibility
            return Ok(data.to_vec());
        }
        if data.len() < ENCRYPTED_STORAGE_MAGIC.len() + NONCE_LEN + 16 {
            return Err("Corrupted encrypted storage payload: too short".to_string());
        }
        let nonce_start = ENCRYPTED_STORAGE_MAGIC.len();
        let nonce_end = nonce_start + NONCE_LEN;
        let nonce = Nonce::from_slice(&data[nonce_start..nonce_end]);
        let ciphertext = &data[nonce_end..];
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Storage decryption failed (invalid key or corrupted data): {e}"))
    }
}

pub fn should_encrypt_key(key: &str) -> bool {
    key != "config/jwt_secret.bin"
}

#[derive(Clone)]
pub enum StorageBackend {
    S3(aws_sdk_s3::Client),
    Memory(Arc<Mutex<MemoryBackend>>),
}

#[derive(Clone)]
pub struct Storage {
    pub backend: StorageBackend,
    pub cipher: Option<Arc<StorageCipher>>,
    pub sse_algorithm: Option<String>,
    pub sse_kms_key_id: Option<String>,
}

#[allow(non_snake_case)]
impl Storage {
    pub fn S3(client: aws_sdk_s3::Client) -> Self {
        Self {
            backend: StorageBackend::S3(client),
            cipher: None,
            sse_algorithm: None,
            sse_kms_key_id: None,
        }
    }

    pub fn Memory(mem: Arc<Mutex<MemoryBackend>>) -> Self {
        Self {
            backend: StorageBackend::Memory(mem),
            cipher: None,
            sse_algorithm: None,
            sse_kms_key_id: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_cipher(mut self, cipher: StorageCipher) -> Self {
        self.cipher = Some(Arc::new(cipher));
        self
    }

    pub fn set_cipher(&mut self, cipher: StorageCipher) {
        self.cipher = Some(Arc::new(cipher));
    }

    #[allow(dead_code)]
    pub fn with_sse(mut self, sse_algorithm: Option<String>, sse_kms_key_id: Option<String>) -> Self {
        self.sse_algorithm = sse_algorithm;
        self.sse_kms_key_id = sse_kms_key_id;
        self
    }

    pub fn set_sse(&mut self, sse_algorithm: Option<String>, sse_kms_key_id: Option<String>) {
        self.sse_algorithm = sse_algorithm;
        self.sse_kms_key_id = sse_kms_key_id;
    }
}

#[derive(Default)]
pub struct MemoryBackend {
    pub files: HashMap<String, Vec<u8>>,
    pub content_types: HashMap<String, String>,
    pub multipart_uploads: HashMap<String, HashMap<i32, Vec<u8>>>,
    /// Maps upload_id to object key
    pub multipart_upload_keys: HashMap<String, String>,
    /// Last modification time (unix seconds) per object key. Kept so that
    /// share expiry, upload_time reporting and cleanup work in memory mode.
    pub last_modified: HashMap<String, i64>,
    /// Time of last activity (unix seconds) per in-progress multipart upload,
    /// so abandoned multipart uploads can be cleaned up in memory mode too.
    pub multipart_upload_times: HashMap<String, i64>,
}

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub key: String,
    pub size: i64,
    pub last_modified_secs: i64,
}

#[derive(Debug, Clone)]
pub struct HeadObjectInfo {
    pub size: i64,
    pub last_modified_secs: i64,
    pub e_tag: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PresignedRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct CompletedPart {
    pub e_tag: String,
    pub part_number: i32,
    pub checksum_sha256: Option<String>,
}

pub struct UploadPartRequest<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub upload_id: &'a str,
    pub part_number: i32,
    pub content_length: i64,
    pub checksum_sha256: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct MultipartUploadInfo {
    pub key: String,
    pub upload_id: String,
    pub initiated_secs: i64,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn memory_etag(data: &[u8]) -> String {
    format!("\"{:x}\"", Sha256::digest(data))
}

impl Storage {
    pub fn supports_presigning(&self) -> bool {
        matches!(self.backend, StorageBackend::S3(_))
    }

    fn collect_presigned_request(
        request: aws_sdk_s3::presigning::PresignedRequest,
    ) -> PresignedRequest {
        let headers = request
            .headers()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();

        PresignedRequest {
            method: request.method().to_string(),
            url: request.uri().to_string(),
            headers,
        }
    }

    pub async fn presign_put_object(
        &self,
        bucket: &str,
        key: &str,
        content_length: i64,
        checksum_sha256: &str,
        expires_in: Duration,
    ) -> Result<PresignedRequest, String> {
        let StorageBackend::S3(client) = &self.backend else {
            return Err("Direct transfers require S3 storage".to_string());
        };
        let config = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in)
            .map_err(|e| e.to_string())?;
        let mut builder = client
            .put_object()
            .bucket(bucket)
            .key(key)
            .content_length(content_length)
            .content_type("application/octet-stream")
            .checksum_sha256(checksum_sha256)
            .if_none_match("*");

        if let Some(ref sse) = self.sse_algorithm {
            if sse.eq_ignore_ascii_case("AES256") {
                builder = builder.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256);
            } else if sse.eq_ignore_ascii_case("aws:kms") {
                builder = builder.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms);
                if let Some(ref kms_id) = self.sse_kms_key_id {
                    builder = builder.ssekms_key_id(kms_id);
                }
            }
        }

        let request = builder
            .presigned(config)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self::collect_presigned_request(request))
    }

    pub async fn presign_upload_part(
        &self,
        request: UploadPartRequest<'_>,
        expires_in: Duration,
    ) -> Result<PresignedRequest, String> {
        let StorageBackend::S3(client) = &self.backend else {
            return Err("Direct transfers require S3 storage".to_string());
        };
        let config = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in)
            .map_err(|e| e.to_string())?;
        let mut builder = client
            .upload_part()
            .bucket(request.bucket)
            .key(request.key)
            .upload_id(request.upload_id)
            .part_number(request.part_number)
            .content_length(request.content_length);
        if let Some(checksum) = request.checksum_sha256 {
            builder = builder.checksum_sha256(checksum);
        }
        let request = builder
            .presigned(config)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self::collect_presigned_request(request))
    }

    pub async fn presign_get_object(
        &self,
        bucket: &str,
        key: &str,
        expires_in: Duration,
    ) -> Result<PresignedRequest, String> {
        let StorageBackend::S3(client) = &self.backend else {
            return Err("Direct transfers require S3 storage".to_string());
        };
        let config = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in)
            .map_err(|e| e.to_string())?;
        let request = client
            .get_object()
            .bucket(bucket)
            .key(key)
            .presigned(config)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self::collect_presigned_request(request))
    }

    pub async fn get_object_bytes(&self, bucket: &str, key: &str) -> Result<Vec<u8>, String> {
        let raw = match &self.backend {
            StorageBackend::S3(client) => {
                let res = client
                    .get_object()
                    .bucket(bucket)
                    .key(key)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                let bytes = res
                    .body
                    .collect()
                    .await
                    .map_err(|e| e.to_string())?
                    .into_bytes();
                bytes.to_vec()
            }
            StorageBackend::Memory(mem) => {
                let m = mem.lock().await;
                m.files
                    .get(key)
                    .cloned()
                    .ok_or_else(|| "Not found".to_string())?
            }
        };

        if should_encrypt_key(key) {
            if let Some(ref cipher) = self.cipher {
                return cipher.decrypt(&raw);
            }
        }
        Ok(raw)
    }

    /// Fetch an object, distinguishing "does not exist" from a real storage
    /// failure. Callers that would otherwise mistake an outage for an empty
    /// document (and then overwrite it) must use this instead of
    /// `get_object_bytes`.
    pub async fn get_object_bytes_optional(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        let maybe_raw = match &self.backend {
            StorageBackend::S3(client) => match client.get_object().bucket(bucket).key(key).send().await {
                Ok(response) => {
                    let bytes = response
                        .body
                        .collect()
                        .await
                        .map_err(|e| e.to_string())?
                        .into_bytes()
                        .to_vec();
                    Some(bytes)
                }
                Err(error) => {
                    use aws_smithy_types::error::metadata::ProvideErrorMetadata;
                    if let aws_sdk_s3::error::SdkError::ServiceError(service_error) = &error {
                        let code = service_error.err().code().unwrap_or_default();
                        if matches!(code, "NoSuchKey" | "NotFound" | "404") {
                            return Ok(None);
                        }
                    }
                    return Err(error.to_string());
                }
            },
            StorageBackend::Memory(mem) => {
                let m = mem.lock().await;
                m.files.get(key).cloned()
            }
        };

        match maybe_raw {
            Some(raw) => {
                if should_encrypt_key(key) {
                    if let Some(ref cipher) = self.cipher {
                        return cipher.decrypt(&raw).map(Some);
                    }
                }
                Ok(Some(raw))
            }
            None => Ok(None),
        }
    }

    pub async fn get_object_bytes_with_etag(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(Vec<u8>, String)>, String> {
        let maybe_raw = match &self.backend {
            StorageBackend::S3(client) => {
                let response = match client.get_object().bucket(bucket).key(key).send().await {
                    Ok(response) => response,
                    Err(error) => {
                        use aws_smithy_types::error::metadata::ProvideErrorMetadata;
                        if let aws_sdk_s3::error::SdkError::ServiceError(service_error) = &error {
                            let code = service_error.err().code().unwrap_or_default();
                            if matches!(code, "NoSuchKey" | "NotFound" | "404") {
                                return Ok(None);
                            }
                        }
                        return Err(error.to_string());
                    }
                };
                let e_tag = response
                    .e_tag()
                    .map(str::to_string)
                    .ok_or_else(|| "S3 object has no ETag".to_string())?;
                let bytes = response
                    .body
                    .collect()
                    .await
                    .map_err(|e| e.to_string())?
                    .into_bytes()
                    .to_vec();
                Some((bytes, e_tag))
            }
            StorageBackend::Memory(mem) => {
                let m = mem.lock().await;
                m.files.get(key).cloned().map(|bytes| {
                    let e_tag = memory_etag(&bytes);
                    (bytes, e_tag)
                })
            }
        };

        match maybe_raw {
            Some((raw, etag)) => {
                if should_encrypt_key(key) {
                    if let Some(ref cipher) = self.cipher {
                        let decrypted = cipher.decrypt(&raw)?;
                        return Ok(Some((decrypted, etag)));
                    }
                }
                Ok(Some((raw, etag)))
            }
            None => Ok(None),
        }
    }

    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        data: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<(), String> {
        let payload = if should_encrypt_key(key) {
            if let Some(ref cipher) = self.cipher {
                cipher.encrypt(&data)?
            } else {
                data
            }
        } else {
            data
        };

        match &self.backend {
            StorageBackend::S3(client) => {
                let mut req = client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    .body(aws_sdk_s3::primitives::ByteStream::from(payload));
                if let Some(ct) = content_type {
                    req = req.content_type(ct);
                }
                if let Some(ref sse) = self.sse_algorithm {
                    if sse.eq_ignore_ascii_case("AES256") {
                        req = req.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256);
                    } else if sse.eq_ignore_ascii_case("aws:kms") {
                        req = req.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms);
                        if let Some(ref kms_id) = self.sse_kms_key_id {
                            req = req.ssekms_key_id(kms_id);
                        }
                    }
                }
                req.send().await.map_err(|e| e.to_string())?;
                Ok(())
            }
            StorageBackend::Memory(mem) => {
                let mut m = mem.lock().await;
                m.files.insert(key.to_string(), payload);
                m.last_modified.insert(key.to_string(), now_secs());
                if let Some(ct) = content_type {
                    m.content_types.insert(key.to_string(), ct.to_string());
                } else {
                    m.content_types.remove(key);
                }
                Ok(())
            }
        }
    }

    pub async fn head_object_info(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<HeadObjectInfo>, String> {
        match &self.backend {
            StorageBackend::S3(client) => {
                match client.head_object().bucket(bucket).key(key).send().await {
                    Ok(output) => Ok(Some(HeadObjectInfo {
                        size: output.content_length().unwrap_or(0),
                        last_modified_secs: output.last_modified().map(|d| d.secs()).unwrap_or(0),
                        e_tag: output.e_tag().map(str::to_string),
                    })),
                    Err(error) => {
                        use aws_smithy_types::error::metadata::ProvideErrorMetadata;
                        if let aws_sdk_s3::error::SdkError::ServiceError(service_error) = &error {
                            let code = service_error.err().code().unwrap_or_default();
                            if matches!(code, "NotFound" | "NoSuchKey" | "404") {
                                return Ok(None);
                            }
                        }
                        Err(error.to_string())
                    }
                }
            }
            StorageBackend::Memory(mem) => {
                let m = mem.lock().await;
                Ok(m.files.get(key).map(|data| HeadObjectInfo {
                    size: data.len() as i64,
                    last_modified_secs: m.last_modified.get(key).copied().unwrap_or_else(now_secs),
                    e_tag: Some(memory_etag(data)),
                }))
            }
        }
    }

    pub async fn put_object_if_absent(
        &self,
        bucket: &str,
        key: &str,
        data: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<bool, String> {
        let payload = if should_encrypt_key(key) {
            if let Some(ref cipher) = self.cipher {
                cipher.encrypt(&data)?
            } else {
                data
            }
        } else {
            data
        };

        match &self.backend {
            StorageBackend::S3(client) => {
                let mut request = client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    .if_none_match("*")
                    .body(aws_sdk_s3::primitives::ByteStream::from(payload));
                if let Some(content_type) = content_type {
                    request = request.content_type(content_type);
                }
                if let Some(ref sse) = self.sse_algorithm {
                    if sse.eq_ignore_ascii_case("AES256") {
                        request = request.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256);
                    } else if sse.eq_ignore_ascii_case("aws:kms") {
                        request = request.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms);
                        if let Some(ref kms_id) = self.sse_kms_key_id {
                            request = request.ssekms_key_id(kms_id);
                        }
                    }
                }
                match request.send().await {
                    Ok(_) => Ok(true),
                    Err(error) => {
                        use aws_smithy_types::error::metadata::ProvideErrorMetadata;
                        if let aws_sdk_s3::error::SdkError::ServiceError(service_error) = &error {
                            let code = service_error.err().code().unwrap_or_default();
                            if matches!(
                                code,
                                "PreconditionFailed" | "ConditionalRequestConflict" | "412" | "409"
                            ) {
                                return Ok(false);
                            }
                        }
                        Err(error.to_string())
                    }
                }
            }
            StorageBackend::Memory(mem) => {
                let mut m = mem.lock().await;
                if m.files.contains_key(key) {
                    return Ok(false);
                }
                m.files.insert(key.to_string(), payload);
                m.last_modified.insert(key.to_string(), now_secs());
                if let Some(content_type) = content_type {
                    m.content_types
                        .insert(key.to_string(), content_type.to_string());
                } else {
                    m.content_types.remove(key);
                }
                Ok(true)
            }
        }
    }

    pub async fn put_object_if_match(
        &self,
        bucket: &str,
        key: &str,
        data: Vec<u8>,
        content_type: Option<&str>,
        e_tag: &str,
    ) -> Result<bool, String> {
        let payload = if should_encrypt_key(key) {
            if let Some(ref cipher) = self.cipher {
                cipher.encrypt(&data)?
            } else {
                data
            }
        } else {
            data
        };

        match &self.backend {
            StorageBackend::S3(client) => {
                let mut request = client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    .if_match(e_tag)
                    .body(aws_sdk_s3::primitives::ByteStream::from(payload));
                if let Some(content_type) = content_type {
                    request = request.content_type(content_type);
                }
                if let Some(ref sse) = self.sse_algorithm {
                    if sse.eq_ignore_ascii_case("AES256") {
                        request = request.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256);
                    } else if sse.eq_ignore_ascii_case("aws:kms") {
                        request = request.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms);
                        if let Some(ref kms_id) = self.sse_kms_key_id {
                            request = request.ssekms_key_id(kms_id);
                        }
                    }
                }
                match request.send().await {
                    Ok(_) => Ok(true),
                    Err(error) => {
                        use aws_smithy_types::error::metadata::ProvideErrorMetadata;
                        if let aws_sdk_s3::error::SdkError::ServiceError(service_error) = &error {
                            let code = service_error.err().code().unwrap_or_default();
                            if matches!(
                                code,
                                "PreconditionFailed" | "ConditionalRequestConflict" | "412" | "409"
                            ) {
                                return Ok(false);
                            }
                        }
                        Err(error.to_string())
                    }
                }
            }
            StorageBackend::Memory(mem) => {
                let mut m = mem.lock().await;
                let Some(current) = m.files.get(key) else {
                    return Ok(false);
                };
                if memory_etag(current) != e_tag {
                    return Ok(false);
                }
                m.files.insert(key.to_string(), payload);
                m.last_modified.insert(key.to_string(), now_secs());
                if let Some(content_type) = content_type {
                    m.content_types
                        .insert(key.to_string(), content_type.to_string());
                } else {
                    m.content_types.remove(key);
                }
                Ok(true)
            }
        }
    }

    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), String> {
        match &self.backend {
            StorageBackend::S3(client) => {
                client
                    .delete_object()
                    .bucket(bucket)
                    .key(key)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            StorageBackend::Memory(mem) => {
                let mut m = mem.lock().await;
                m.files.remove(key);
                m.content_types.remove(key);
                m.last_modified.remove(key);
                Ok(())
            }
        }
    }

    /// Delete many objects in one round trip. S3 supports up to 1000 keys per
    /// DeleteObjects call, so this is dramatically faster than a per-key loop.
    pub async fn delete_objects_batch(&self, bucket: &str, keys: &[String]) -> Result<(), String> {
        if keys.is_empty() {
            return Ok(());
        }
        match &self.backend {
            StorageBackend::S3(client) => {
                for chunk in keys.chunks(1000) {
                    let mut objects = Vec::new();
                    for k in chunk {
                        objects.push(
                            aws_sdk_s3::types::ObjectIdentifier::builder()
                                .key(k.clone())
                                .build()
                                .map_err(|e| format!("Failed to build ObjectIdentifier: {}", e))?,
                        );
                    }
                    let delete = aws_sdk_s3::types::Delete::builder()
                        .set_objects(Some(objects))
                        .build()
                        .map_err(|e| format!("Failed to build Delete request: {}", e))?;
                    let res = client
                        .delete_objects()
                        .bucket(bucket)
                        .delete(delete)
                        .send()
                        .await
                        .map_err(|e| e.to_string())?;
                    let errors = res.errors();
                    if !errors.is_empty() {
                        let first = errors.first().and_then(|e| e.key()).unwrap_or("unknown");
                        return Err(format!("S3 batch delete failed for key '{}'", first));
                    }
                }
                Ok(())
            }
            StorageBackend::Memory(mem) => {
                let mut m = mem.lock().await;
                for k in keys {
                    m.files.remove(k);
                    m.content_types.remove(k);
                    m.last_modified.remove(k);
                }
                Ok(())
            }
        }
    }

    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        max_keys: Option<i32>,
    ) -> Result<Vec<ObjectInfo>, String> {
        let limit = max_keys.map(|value| value.max(0) as usize);
        if limit == Some(0) {
            return Ok(Vec::new());
        }
        match &self.backend {
            StorageBackend::S3(client) => {
                let mut req = client.list_objects_v2().bucket(bucket);
                if let Some(p) = prefix {
                    req = req.prefix(p);
                }
                if let Some(mk) = max_keys {
                    req = req.max_keys(mk);
                }
                let mut keys = Vec::new();
                let mut response = req.into_paginator().send();
                while let Some(res) = response.next().await {
                    if let Ok(page) = res {
                        for obj in page.contents() {
                            if let Some(k) = obj.key() {
                                keys.push(ObjectInfo {
                                    key: k.to_string(),
                                    size: obj.size().unwrap_or(0),
                                    last_modified_secs: obj
                                        .last_modified()
                                        .map(|d| d.secs())
                                        .unwrap_or(0),
                                });
                                if limit.is_some_and(|limit| keys.len() >= limit) {
                                    return Ok(keys);
                                }
                            }
                        }
                    } else if let Err(error) = res {
                        return Err(format!("S3 list error: {error}"));
                    }
                }
                Ok(keys)
            }
            StorageBackend::Memory(mem) => {
                let m = mem.lock().await;
                let mut keys: Vec<_> = m
                    .files
                    .iter()
                    .filter(|(key, _)| prefix.is_none_or(|prefix| key.starts_with(prefix)))
                    .map(|(key, value)| ObjectInfo {
                        key: key.clone(),
                        size: value.len() as i64,
                        last_modified_secs: m
                            .last_modified
                            .get(key)
                            .copied()
                            .unwrap_or_else(now_secs),
                    })
                    .collect();
                keys.sort_by(|left, right| left.key.cmp(&right.key));
                if let Some(limit) = limit {
                    keys.truncate(limit);
                }
                Ok(keys)
            }
        }
    }

    pub async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: Option<&str>,
    ) -> Result<String, String> {
        match &self.backend {
            StorageBackend::S3(client) => {
                let mut req = client.create_multipart_upload().bucket(bucket).key(key);
                req = req.checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Sha256);
                if let Some(ct) = content_type {
                    req = req.content_type(ct);
                }
                if let Some(ref sse) = self.sse_algorithm {
                    if sse.eq_ignore_ascii_case("AES256") {
                        req = req.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256);
                    } else if sse.eq_ignore_ascii_case("aws:kms") {
                        req = req.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms);
                        if let Some(ref kms_id) = self.sse_kms_key_id {
                            req = req.ssekms_key_id(kms_id);
                        }
                    }
                }
                let res = req.send().await.map_err(|e| e.to_string())?;
                res.upload_id()
                    .filter(|upload_id| !upload_id.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| "S3 returned no multipart upload ID".to_string())
            }
            StorageBackend::Memory(mem) => {
                let mut m = mem.lock().await;
                let upload_id = uuid::Uuid::new_v4().to_string();
                m.multipart_uploads
                    .insert(upload_id.clone(), HashMap::new());
                m.multipart_upload_keys
                    .insert(upload_id.clone(), key.to_string());
                m.multipart_upload_times
                    .insert(upload_id.clone(), now_secs());
                Ok(upload_id)
            }
        }
    }

    pub async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<(), String> {
        match &self.backend {
            StorageBackend::S3(client) => {
                let mut builder = aws_sdk_s3::types::CompletedMultipartUpload::builder();
                for p in parts {
                    let mut part_builder = aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(p.part_number)
                        .e_tag(p.e_tag);
                    if let Some(cs) = p.checksum_sha256 {
                        part_builder = part_builder.checksum_sha256(cs);
                    }
                    builder = builder.parts(part_builder.build());
                }
                client
                    .complete_multipart_upload()
                    .bucket(bucket)
                    .key(key)
                    .upload_id(upload_id)
                    .if_none_match("*")
                    .multipart_upload(builder.build())
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            StorageBackend::Memory(mem) => {
                let mut m = mem.lock().await;
                m.multipart_upload_keys.remove(upload_id);
                if let Some(upload) = m.multipart_uploads.remove(upload_id) {
                    let mut data = Vec::new();
                    let mut sorted_parts: Vec<_> = upload.into_iter().collect();
                    sorted_parts.sort_by_key(|(k, _)| *k);
                    for (_, part_data) in sorted_parts {
                        data.extend(part_data);
                    }
                    m.files.insert(key.to_string(), data);
                    m.last_modified.insert(key.to_string(), now_secs());
                    m.multipart_upload_times.remove(upload_id);
                    Ok(())
                } else {
                    Err("Upload ID not found".to_string())
                }
            }
        }
    }

    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), String> {
        match &self.backend {
            StorageBackend::S3(client) => {
                client
                    .abort_multipart_upload()
                    .bucket(bucket)
                    .key(key)
                    .upload_id(upload_id)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            StorageBackend::Memory(mem) => {
                let mut m = mem.lock().await;
                m.multipart_uploads.remove(upload_id);
                m.multipart_upload_keys.remove(upload_id);
                m.multipart_upload_times.remove(upload_id);
                Ok(())
            }
        }
    }

    /// List all in-progress multipart uploads in the bucket (paginated).
    pub async fn list_multipart_uploads(
        &self,
        bucket: &str,
    ) -> Result<Vec<MultipartUploadInfo>, String> {
        match &self.backend {
            StorageBackend::S3(client) => {
                let mut out = Vec::new();
                let mut key_marker: Option<String> = None;
                let mut upload_id_marker: Option<String> = None;
                loop {
                    let mut req = client
                        .list_multipart_uploads()
                        .bucket(bucket)
                        .max_uploads(1000);
                    if let Some(km) = &key_marker {
                        req = req.key_marker(km.clone());
                    }
                    if let Some(um) = &upload_id_marker {
                        req = req.upload_id_marker(um.clone());
                    }
                    let page = req.send().await.map_err(|e| e.to_string())?;
                    for u in page.uploads() {
                        if let (Some(k), Some(id)) = (u.key(), u.upload_id()) {
                            out.push(MultipartUploadInfo {
                                key: k.to_string(),
                                upload_id: id.to_string(),
                                initiated_secs: u.initiated().map(|d| d.secs()).unwrap_or(0),
                            });
                        }
                    }
                    if !page.is_truncated().unwrap_or(false) {
                        break;
                    }
                    key_marker = page.next_key_marker().map(|s| s.to_string());
                    upload_id_marker = page.next_upload_id_marker().map(|s| s.to_string());
                    if key_marker.is_none() && upload_id_marker.is_none() {
                        break;
                    }
                }
                Ok(out)
            }
            StorageBackend::Memory(mem) => {
                let m = mem.lock().await;
                Ok(m.multipart_uploads
                    .keys()
                    .map(|id| MultipartUploadInfo {
                        key: m
                            .multipart_upload_keys
                            .get(id)
                            .cloned()
                            .unwrap_or_default(),
                        upload_id: id.clone(),
                        initiated_secs: m
                            .multipart_upload_times
                            .get(id)
                            .copied()
                            .unwrap_or_else(now_secs),
                    })
                    .collect())
            }
        }
    }
}
