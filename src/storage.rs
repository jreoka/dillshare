use axum::body::Body;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

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

pub struct GetObjectOutput {
    pub body: Body,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub content_range: Option<String>,
}

#[derive(Debug)]
pub enum StorageError {
    NotFound(String),
    InvalidRange(String),
    Other(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::NotFound(m) => write!(f, "Not found: {}", m),
            StorageError::InvalidRange(m) => write!(f, "Invalid range: {}", m),
            StorageError::Other(m) => write!(f, "{}", m),
        }
    }
}

impl std::error::Error for StorageError {}

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub key: String,
    pub size: i64,
    pub last_modified_secs: i64,
}

#[derive(Debug, Clone)]
pub struct CompletedPart {
    pub e_tag: String,
    pub part_number: i32,
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

/// Parse an HTTP byte-range header value ("bytes=...", first range wins) into
/// an inclusive start / exclusive end pair clamped to `len`.
///
/// Returns `Err(())` when the range cannot be satisfied (start past EOF,
/// inverted range, zero-length suffix, malformed syntax, or a range against an
/// empty object). S3-compatible semantics.
fn parse_byte_range(range_header: &str, len: usize) -> Result<(usize, usize), ()> {
    let spec = range_header.strip_prefix("bytes=").ok_or(())?;
    let spec = spec.split(',').next().unwrap_or("").trim();
    let (start, end) = if let Some(suffix) = spec.strip_prefix('-') {
        let n: usize = suffix.parse().map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        let start = len.saturating_sub(n);
        (start, len)
    } else if let Some(idx) = spec.find('-') {
        let start_s = &spec[..idx];
        let end_s = &spec[idx + 1..];
        let start: usize = if start_s.is_empty() {
            0
        } else {
            start_s.parse().map_err(|_| ())?
        };
        if end_s.is_empty() {
            (start, len)
        } else {
            let end_incl: usize = end_s.parse().map_err(|_| ())?;
            if end_incl < start {
                return Err(());
            }
            (start, end_incl.saturating_add(1))
        }
    } else {
        return Err(());
    };

    if len == 0 || start >= len {
        return Err(());
    }
    Ok((start, end.min(len).max(start)))
}

impl Storage {
    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
        range_header: Option<String>,
    ) -> Result<GetObjectOutput, StorageError> {
        match self {
            Storage::S3(client) => {
                let mut req = client.get_object().bucket(bucket).key(key);
                if let Some(r) = range_header {
                    req = req.range(r);
                }
                match req.send().await {
                    Ok(res) => {
                        let ct = res.content_type.clone();
                        let cl = res.content_length;
                        let cr = res.content_range.clone();
                        let stream = tokio_util::io::ReaderStream::new(res.body.into_async_read());
                        Ok(GetObjectOutput {
                            body: Body::from_stream(stream),
                            content_type: ct,
                            content_length: cl.map(|v| v as u64),
                            content_range: cr,
                        })
                    }
                    Err(e) => match &e {
                        aws_sdk_s3::error::SdkError::ServiceError(se) => {
                            use aws_smithy_types::error::metadata::ProvideErrorMetadata;
                            match se.err() {
                                aws_sdk_s3::operation::get_object::GetObjectError::NoSuchKey(_) => {
                                    Err(StorageError::NotFound(format!(
                                        "Object '{}' not found in bucket '{}'",
                                        key, bucket
                                    )))
                                }
                                err => {
                                    if err.code() == Some("InvalidRange") {
                                        Err(StorageError::InvalidRange(e.to_string()))
                                    } else {
                                        Err(StorageError::Other(e.to_string()))
                                    }
                                }
                            }
                        }
                        _ => Err(StorageError::Other(e.to_string())),
                    },
                }
            }
            Storage::Memory(mem) => {
                let m = mem.lock().await;
                if let Some(data) = m.files.get(key) {
                    let (start, end) = if let Some(ref r) = range_header {
                        match parse_byte_range(r, data.len()) {
                            Ok(range) => range,
                            Err(()) => {
                                return Err(StorageError::InvalidRange(format!(
                                    "Requested range not satisfiable for object '{}'",
                                    key
                                )))
                            }
                        }
                    } else {
                        (0, data.len())
                    };
                    let slice = data[start..end].to_vec();
                    let content_range = if range_header.is_some() {
                        Some(format!(
                            "bytes {}-{}/{}",
                            start,
                            end.saturating_sub(1),
                            data.len()
                        ))
                    } else {
                        None
                    };
                    let slice_len = slice.len();
                    Ok(GetObjectOutput {
                        body: Body::from(slice),
                        content_type: m.content_types.get(key).cloned(),
                        content_length: Some(slice_len as u64),
                        content_range,
                    })
                } else {
                    Err(StorageError::NotFound(format!(
                        "Object '{}' not found in bucket '{}'",
                        key, bucket
                    )))
                }
            }
        }
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
                }
                Ok(())
            }
        }
    }

    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<bool, String> {
        match self {
            Storage::S3(client) => {
                match client.head_object().bucket(bucket).key(key).send().await {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            Storage::Memory(mem) => {
                let m = mem.lock().await;
                Ok(m.files.contains_key(key))
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
                            }
                        }
                    } else {
                        return Err("S3 list error".to_string());
                    }
                }
                Ok(keys)
            }
            Storage::Memory(mem) => {
                let m = mem.lock().await;
                let mut keys = Vec::new();
                for (k, v) in &m.files {
                    if let Some(p) = prefix {
                        if !k.starts_with(p) {
                            continue;
                        }
                    }
                    keys.push(ObjectInfo {
                        key: k.clone(),
                        size: v.len() as i64,
                        last_modified_secs: m
                            .last_modified
                            .get(k)
                            .copied()
                            .unwrap_or_else(now_secs),
                    });
                    if let Some(mk) = max_keys {
                        if keys.len() as i32 >= mk {
                            break;
                        }
                    }
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
                if let Some(ct) = content_type {
                    req = req.content_type(ct);
                }
                let res = req.send().await.map_err(|e| e.to_string())?;
                Ok(res.upload_id().unwrap_or_default().to_string())
            }
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                let upload_id = uuid::Uuid::new_v4().to_string();
                m.multipart_uploads
                    .insert(upload_id.clone(), HashMap::new());
                m.multipart_upload_times.insert(upload_id.clone(), now_secs());
                Ok(upload_id)
            }
        }
    }

    pub async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        data: Vec<u8>,
    ) -> Result<String, String> {
        if !(1..=10_000).contains(&part_number) {
            return Err(format!(
                "Part number {} out of range (must be 1-10000)",
                part_number
            ));
        }
        match self {
            Storage::S3(client) => {
                let res = client
                    .upload_part()
                    .bucket(bucket)
                    .key(key)
                    .upload_id(upload_id)
                    .part_number(part_number)
                    .body(aws_sdk_s3::primitives::ByteStream::from(data))
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(res.e_tag().unwrap_or_default().to_string())
            }
            Storage::Memory(mem) => {
                let mut m = mem.lock().await;
                if let Some(upload) = m.multipart_uploads.get_mut(upload_id) {
                    upload.insert(part_number, data);
                    m.multipart_upload_times.insert(upload_id.to_string(), now_secs());
                    Ok("mem-etag".to_string())
                } else {
                    Err("Upload ID not found".to_string())
                }
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
                            .build(),
                    );
                }
                client
                    .complete_multipart_upload()
                    .bucket(bucket)
                    .key(key)
                    .upload_id(upload_id)
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
                    let mut req = client.list_multipart_uploads().bucket(bucket).max_uploads(1000);
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
