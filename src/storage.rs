use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use sha2::{Digest, Sha256};

#[derive(Clone)]
pub enum Storage {
    S3(aws_sdk_s3::Client),
    Memory(Arc<Mutex<MemoryBackend>>),
}

#[derive(Default)]
pub struct MemoryBackend {
    pub files: HashMap<String, Vec<u8>>,
    pub content_types: HashMap<String, String>,
    pub multipart_uploads: HashMap<String, HashMap<i32, Vec<u8>>>,
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
    pub checksum_sha256: String,
}

pub struct UploadPartRequest<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub upload_id: &'a str,
    pub part_number: i32,
    pub content_length: i64,
    pub checksum_sha256: &'a str,
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
        matches!(self, Storage::S3(_))
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
        let Storage::S3(client) = self else {
            return Err("Direct transfers require S3 storage".to_string());
        };
        let config = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in)
            .map_err(|e| e.to_string())?;
        let request = client
            .put_object()
            .bucket(bucket)
            .key(key)
            .content_length(content_length)
            .content_type("application/octet-stream")
            .checksum_sha256(checksum_sha256)
            .if_none_match("*")
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
        let Storage::S3(client) = self else {
            return Err("Direct transfers require S3 storage".to_string());
        };
        let config = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in)
            .map_err(|e| e.to_string())?;
        let request = client
            .upload_part()
            .bucket(request.bucket)
            .key(request.key)
            .upload_id(request.upload_id)
            .part_number(request.part_number)
            .content_length(request.content_length)
            .checksum_sha256(request.checksum_sha256)
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
        let Storage::S3(client) = self else {
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
        match self {
            Storage::S3(client) => {
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
                Ok(bytes.to_vec())
            }
            Storage::Memory(mem) => {
                let m = mem.lock().await;
                m.files
                    .get(key)
                    .cloned()
                    .ok_or_else(|| "Not found".to_string())
            }
        }
    }

    pub async fn get_object_bytes_with_etag(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(Vec<u8>, String)>, String> {
        match self {
            Storage::S3(client) => {
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
                Ok(Some((bytes, e_tag)))
            }
            Storage::Memory(mem) => {
                let m = mem.lock().await;
                Ok(m.files.get(key).cloned().map(|bytes| {
                    let e_tag = memory_etag(&bytes);
                    (bytes, e_tag)
                }))
            }
        }
    }

    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        data: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<(), String> {
        match self {
            Storage::S3(client) => {
                let mut req = client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    .body(aws_sdk_s3::primitives::ByteStream::from(data));
                if let Some(ct) = content_type {
                    req = req.content_type(ct);
                }
                req.send().await.map_err(|e| e.to_string())?;
                Ok(())
            }
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                m.files.insert(key.to_string(), data);
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
        match self {
            Storage::S3(client) => {
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
            Storage::Memory(mem) => {
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
        match self {
            Storage::S3(client) => {
                let mut request = client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    .if_none_match("*")
                    .body(aws_sdk_s3::primitives::ByteStream::from(data));
                if let Some(content_type) = content_type {
                    request = request.content_type(content_type);
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
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                if m.files.contains_key(key) {
                    return Ok(false);
                }
                m.files.insert(key.to_string(), data);
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
        match self {
            Storage::S3(client) => {
                let mut request = client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    .if_match(e_tag)
                    .body(aws_sdk_s3::primitives::ByteStream::from(data));
                if let Some(content_type) = content_type {
                    request = request.content_type(content_type);
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
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                let Some(current) = m.files.get(key) else {
                    return Ok(false);
                };
                if memory_etag(current) != e_tag {
                    return Ok(false);
                }
                m.files.insert(key.to_string(), data);
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
        match self {
            Storage::S3(client) => {
                client
                    .delete_object()
                    .bucket(bucket)
                    .key(key)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            Storage::Memory(mem) => {
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
        match self {
            Storage::S3(client) => {
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
            Storage::Memory(mem) => {
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
        match self {
            Storage::S3(client) => {
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
            Storage::Memory(mem) => {
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
        match self {
            Storage::S3(client) => {
                let mut req = client.create_multipart_upload().bucket(bucket).key(key);
                req = req.checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Sha256);
                if let Some(ct) = content_type {
                    req = req.content_type(ct);
                }
                let res = req.send().await.map_err(|e| e.to_string())?;
                res.upload_id()
                    .filter(|upload_id| !upload_id.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| "S3 returned no multipart upload ID".to_string())
            }
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                let upload_id = uuid::Uuid::new_v4().to_string();
                m.multipart_uploads
                    .insert(upload_id.clone(), HashMap::new());
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
        match self {
            Storage::S3(client) => {
                let mut builder = aws_sdk_s3::types::CompletedMultipartUpload::builder();
                for p in parts {
                    builder = builder.parts(
                        aws_sdk_s3::types::CompletedPart::builder()
                            .part_number(p.part_number)
                            .e_tag(p.e_tag)
                            .checksum_sha256(p.checksum_sha256)
                            .build(),
                    );
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
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
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
        match self {
            Storage::S3(client) => {
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
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                m.multipart_uploads.remove(upload_id);
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
        match self {
            Storage::S3(client) => {
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
            Storage::Memory(mem) => {
                let m = mem.lock().await;
                Ok(m.multipart_uploads
                    .keys()
                    .map(|id| MultipartUploadInfo {
                        key: String::new(),
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
