//! Shared host registry: one small JSON object per host under an S3 prefix.
//!
//! Each host rewrites its own entry every registry interval. The content rarely changes, so the
//! ETag stays the same and other hosts only fetch entries whose ETag moved; S3's LastModified is
//! the heartbeat. Ages are measured against this host's own LastModified, so local clock skew
//! does not decide liveness.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// EC2 instance: its site is its VPC, which carries no multicast.
    Ec2,
    /// Host outside AWS: a site of its own unless `--site` groups it.
    Metal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Instance ID, or `metal-` plus the machine ID.
    pub host: String,
    /// Hostname, for operators.
    pub name: String,
    pub site: String,
    pub platform: Platform,
    /// Underlay address other hosts terminate GRE on.
    pub endpoint: Ipv4Addr,
    /// Unix time this host first registered. Older hosts keep the relay role, so joins don't reshuffle relays.
    pub since: i64,
}

/// An entry as listed, with its object's LastModified (Unix seconds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub entry: Entry,
    pub modified: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub key: String,
    pub etag: String,
    pub modified: i64,
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn list(&self) -> Result<Vec<Object>>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn put(&self, key: &str, body: Vec<u8>) -> Result<()>;
}

pub fn key_of(host: &str) -> String {
    format!("hosts/{host}.json")
}

/// Registry view kept between syncs, so unchanged entries are not fetched again.
#[derive(Default)]
pub struct Registry {
    cache: BTreeMap<String, (String, Entry)>,
}

impl Registry {
    /// Publishes `own` (unless `publish` is false, for dry runs) and returns every entry with its age in seconds.
    pub async fn sync(&mut self, store: &dyn Store, own: &Entry, publish: bool, now: i64) -> Result<Vec<(Entry, i64)>> {
        let own_key = key_of(&own.host);
        if publish {
            let body = serde_json::to_vec(own).map_err(|e| Error::Backend(format!("registry: {e}")))?;
            store.put(&own_key, body).await?;
        }
        let objects = store.list().await?;
        let reference = objects.iter().find(|o| o.key == own_key && publish).map_or(now, |o| o.modified);
        let mut listed = vec![];
        for object in &objects {
            if !object.key.ends_with(".json") {
                continue;
            }
            let entry = match self.cache.get(&object.key) {
                Some((etag, entry)) if *etag == object.etag => entry.clone(),
                _ => {
                    let Some(body) = store.get(&object.key).await? else { continue };
                    match serde_json::from_slice::<Entry>(&body) {
                        Ok(entry) => {
                            self.cache.insert(object.key.clone(), (object.etag.clone(), entry.clone()));
                            entry
                        }
                        Err(e) => {
                            tracing::warn!("registry_skip key={} error={e}", object.key);
                            continue;
                        }
                    }
                }
            };
            listed.push(Listed { entry, modified: object.modified });
        }
        self.cache.retain(|key, _| objects.iter().any(|o| o.key == *key));
        let mut entries: Vec<(Entry, i64)> =
            listed.into_iter().filter(|l| l.entry.host != own.host).map(|l| (l.entry, (reference - l.modified).max(0))).collect();
        entries.push((own.clone(), 0));
        Ok(entries)
    }
}

/// `since` from this host's existing entry, so a restart keeps its seniority.
pub async fn previous_since(store: &dyn Store, host: &str) -> Result<Option<i64>> {
    let Some(body) = store.get(&key_of(host)).await? else { return Ok(None) };
    Ok(serde_json::from_slice::<Entry>(&body).ok().map(|e| e.since))
}

/// `s3://bucket/prefix` into (bucket, prefix without a trailing slash).
pub fn parse_url(url: &str) -> Result<(String, String)> {
    let rest =
        url.strip_prefix("s3://").ok_or_else(|| Error::Config(format!("--registry {url}: expected s3://bucket/prefix")))?;
    let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    if bucket.is_empty() {
        return Err(Error::Config(format!("--registry {url}: missing bucket")));
    }
    Ok((bucket.to_string(), prefix.trim_matches('/').to_string()))
}

#[cfg(feature = "aws")]
pub use sdk::S3Store;

#[cfg(feature = "aws")]
mod sdk {
    use std::time::Duration;

    use aws_config::retry::RetryConfig;
    use aws_config::timeout::TimeoutConfig;
    use aws_config::{BehaviorVersion, Region};
    use aws_sdk_s3::error::{DisplayErrorContext, ProvideErrorMetadata};
    use aws_sdk_s3::primitives::ByteStream;
    use aws_sdk_s3::Client;

    use super::*;

    pub struct S3Store {
        client: Client,
        bucket: String,
        prefix: String,
    }

    fn api<E: std::error::Error + 'static>(e: E) -> Error {
        Error::Backend(format!("S3 registry: {}", DisplayErrorContext(e)))
    }

    impl S3Store {
        /// `region` is the bucket's region; without it, the standard AWS configuration chain decides.
        pub async fn new(url: &str, region: Option<String>) -> Result<Self> {
            let (bucket, prefix) = parse_url(url)?;
            let timeouts =
                TimeoutConfig::builder().connect_timeout(Duration::from_secs(3)).read_timeout(Duration::from_secs(10)).build();
            let mut loader = aws_config::defaults(BehaviorVersion::latest())
                .timeout_config(timeouts)
                .retry_config(RetryConfig::standard().with_max_attempts(3));
            if let Some(region) = region {
                loader = loader.region(Region::new(region));
            }
            let config = loader.load().await;
            if config.region().is_none() {
                return crate::error::config_err("no AWS region for the registry: pass --registry-region or set AWS_REGION");
            }
            Ok(S3Store { client: Client::new(&config), bucket, prefix })
        }

        fn full(&self, key: &str) -> String {
            if self.prefix.is_empty() {
                key.to_string()
            } else {
                format!("{}/{key}", self.prefix)
            }
        }
    }

    #[async_trait]
    impl Store for S3Store {
        async fn list(&self) -> Result<Vec<Object>> {
            let base = self.full("hosts/");
            let strip = base.len() - "hosts/".len();
            let mut objects = vec![];
            let mut token: Option<String> = None;
            loop {
                let output = self
                    .client
                    .list_objects_v2()
                    .bucket(&self.bucket)
                    .prefix(&base)
                    .set_continuation_token(token.clone())
                    .send()
                    .await
                    .map_err(api)?;
                for o in output.contents() {
                    let (Some(key), Some(etag), Some(modified)) = (o.key(), o.e_tag(), o.last_modified()) else { continue };
                    objects.push(Object { key: key[strip..].to_string(), etag: etag.to_string(), modified: modified.secs() });
                }
                token = output.next_continuation_token().map(str::to_string);
                if token.is_none() {
                    break;
                }
            }
            Ok(objects)
        }

        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            match self.client.get_object().bucket(&self.bucket).key(self.full(key)).send().await {
                Ok(output) => {
                    let body = output.body.collect().await.map_err(|e| Error::Backend(format!("S3 registry: {e}")))?;
                    Ok(Some(body.into_bytes().to_vec()))
                }
                Err(e) if e.as_service_error().is_some_and(|s| s.is_no_such_key() || s.code() == Some("NoSuchKey")) => Ok(None),
                Err(e) => Err(api(e)),
            }
        }

        async fn put(&self, key: &str, body: Vec<u8>) -> Result<()> {
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(self.full(key))
                .content_type("application/json")
                .body(ByteStream::from(body))
                .send()
                .await
                .map_err(api)?;
            Ok(())
        }
    }
}
