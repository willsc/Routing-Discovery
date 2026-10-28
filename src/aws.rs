//! The narrow slice of EC2 used here, behind a trait so tests and dry runs never touch AWS.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::Result;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Ec2Route {
    pub destination_cidr: Option<String>,
    pub destination_ipv6_cidr: Option<String>,
    pub network_interface_id: Option<String>,
    pub gateway_id: Option<String>,
    pub origin: Option<String>,
    pub state: Option<String>,
}

impl Ec2Route {
    pub fn destination(&self) -> Option<&str> {
        self.destination_cidr.as_deref().or(self.destination_ipv6_cidr.as_deref())
    }

    /// Static route created through the API, not the local route or a propagated one.
    pub fn is_static(&self) -> bool {
        self.origin.as_deref() == Some("CreateRoute") && self.gateway_id.as_deref() != Some("local")
    }

    pub fn active(&self) -> bool {
        self.state.as_deref() == Some("active")
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RouteTable {
    pub id: String,
    pub vpc_id: Option<String>,
    pub tags: HashMap<String, String>,
    pub routes: Vec<Ec2Route>,
    pub association_gateway_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetworkInterface {
    pub id: String,
    pub vpc_id: Option<String>,
    pub status: Option<String>,
    pub source_dest_check: Option<bool>,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRequest {
    pub table_id: String,
    pub prefix: String,
    pub ipv6: bool,
    pub network_interface_id: Option<String>,
}

#[async_trait]
pub trait Ec2: Send + Sync {
    async fn describe_route_tables(&self, ids: &[String]) -> Result<Vec<RouteTable>>;
    async fn describe_network_interfaces(&self, ids: &[String]) -> Result<Vec<NetworkInterface>>;
    async fn create_route(&self, request: &RouteRequest) -> Result<()>;
    async fn replace_route(&self, request: &RouteRequest) -> Result<()>;
    async fn delete_route(&self, request: &RouteRequest) -> Result<()>;
}

#[cfg(feature = "aws")]
pub async fn client(region: &str) -> Result<Arc<dyn Ec2>> {
    Ok(Arc::new(sdk::SdkEc2::new(region).await))
}

#[cfg(not(feature = "aws"))]
pub async fn client(_region: &str) -> Result<Arc<dyn Ec2>> {
    crate::error::backend_err("this build lacks the `aws` feature; rebuild with --features aws")
}

#[cfg(feature = "aws")]
mod sdk {
    use std::time::Duration;

    use async_trait::async_trait;
    use aws_config::retry::RetryConfig;
    use aws_config::timeout::TimeoutConfig;
    use aws_config::{BehaviorVersion, Region};
    use aws_sdk_ec2::error::DisplayErrorContext;
    use aws_sdk_ec2::Client;

    use super::*;
    use crate::error::{backend_err, Error};

    pub struct SdkEc2 {
        client: Client,
    }

    impl SdkEc2 {
        pub async fn new(region: &str) -> Self {
            let timeouts =
                TimeoutConfig::builder().connect_timeout(Duration::from_secs(2)).read_timeout(Duration::from_secs(3)).build();
            let config = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region.to_string()))
                .timeout_config(timeouts)
                .retry_config(RetryConfig::standard().with_max_attempts(2))
                .load()
                .await;
            SdkEc2 { client: Client::new(&config) }
        }
    }

    fn api<E: std::error::Error + 'static>(e: E) -> Error {
        Error::Backend(format!("EC2: {}", DisplayErrorContext(e)))
    }

    #[async_trait]
    impl Ec2 for SdkEc2 {
        async fn describe_route_tables(&self, ids: &[String]) -> Result<Vec<RouteTable>> {
            let output = self.client.describe_route_tables().set_route_table_ids(Some(ids.to_vec())).send().await.map_err(api)?;
            Ok(output
                .route_tables()
                .iter()
                .map(|t| RouteTable {
                    id: t.route_table_id().unwrap_or_default().to_string(),
                    vpc_id: t.vpc_id().map(str::to_string),
                    tags: t
                        .tags()
                        .iter()
                        .filter_map(|tag| Some((tag.key()?.to_string(), tag.value().unwrap_or_default().to_string())))
                        .collect(),
                    routes: t
                        .routes()
                        .iter()
                        .map(|r| Ec2Route {
                            destination_cidr: r.destination_cidr_block().map(str::to_string),
                            destination_ipv6_cidr: r.destination_ipv6_cidr_block().map(str::to_string),
                            network_interface_id: r.network_interface_id().map(str::to_string),
                            gateway_id: r.gateway_id().map(str::to_string),
                            origin: r.origin().map(|o| o.as_str().to_string()),
                            state: r.state().map(|s| s.as_str().to_string()),
                        })
                        .collect(),
                    association_gateway_ids: t.associations().iter().filter_map(|a| a.gateway_id()).map(str::to_string).collect(),
                })
                .collect())
        }

        async fn describe_network_interfaces(&self, ids: &[String]) -> Result<Vec<NetworkInterface>> {
            let output = self
                .client
                .describe_network_interfaces()
                .set_network_interface_ids(Some(ids.to_vec()))
                .send()
                .await
                .map_err(api)?;
            Ok(output
                .network_interfaces()
                .iter()
                .map(|e| NetworkInterface {
                    id: e.network_interface_id().unwrap_or_default().to_string(),
                    vpc_id: e.vpc_id().map(str::to_string),
                    status: e.status().map(|s| s.as_str().to_string()),
                    source_dest_check: e.source_dest_check(),
                    addresses: e
                        .private_ip_addresses()
                        .iter()
                        .filter_map(|a| a.private_ip_address())
                        .chain(e.ipv6_addresses().iter().filter_map(|a| a.ipv6_address()))
                        .map(str::to_string)
                        .collect(),
                })
                .collect())
        }

        async fn create_route(&self, r: &RouteRequest) -> Result<()> {
            let mut call = self.client.create_route().route_table_id(&r.table_id);
            call = if r.ipv6 { call.destination_ipv6_cidr_block(&r.prefix) } else { call.destination_cidr_block(&r.prefix) };
            let output = call.set_network_interface_id(r.network_interface_id.clone()).send().await.map_err(api)?;
            if output.r#return() == Some(false) {
                return backend_err("AWS rejected route operation");
            }
            Ok(())
        }

        async fn replace_route(&self, r: &RouteRequest) -> Result<()> {
            let mut call = self.client.replace_route().route_table_id(&r.table_id);
            call = if r.ipv6 { call.destination_ipv6_cidr_block(&r.prefix) } else { call.destination_cidr_block(&r.prefix) };
            call.set_network_interface_id(r.network_interface_id.clone()).send().await.map_err(api)?;
            Ok(())
        }

        async fn delete_route(&self, r: &RouteRequest) -> Result<()> {
            let mut call = self.client.delete_route().route_table_id(&r.table_id);
            call = if r.ipv6 { call.destination_ipv6_cidr_block(&r.prefix) } else { call.destination_cidr_block(&r.prefix) };
            call.send().await.map_err(api)?;
            Ok(())
        }
    }
}
