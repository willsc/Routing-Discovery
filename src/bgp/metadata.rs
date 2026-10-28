//! This instance's identity and ENIs from IMDSv2. Nothing about the host is configured.

use std::net::IpAddr;

use async_trait::async_trait;
use ipnet::IpNet;
use serde::Serialize;

use crate::error::{Error, Result};

#[async_trait]
pub trait Metadata: Send + Sync {
    /// `Ok(None)` for a path IMDS does not have (404), such as `ipv6s` on an IPv4-only ENI.
    async fn get(&self, path: &str) -> Result<Option<String>>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Eni {
    pub id: String,
    pub mac: String,
    pub subnet_id: String,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Host {
    pub instance_id: String,
    pub region: String,
    pub vpc_id: String,
    pub vpc_cidrs: Vec<IpNet>,
    pub enis: Vec<Eni>,
}

impl Host {
    pub fn addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.enis.iter().flat_map(|e| e.addresses.iter().copied())
    }

    pub fn eni_of(&self, address: IpAddr) -> Option<&Eni> {
        self.enis.iter().find(|e| e.addresses.contains(&address))
    }

    pub fn in_vpc(&self, net: &IpNet) -> bool {
        self.vpc_cidrs.iter().any(|c| c.contains(net))
    }

    /// First primary IPv4 address, used as the BGP router ID.
    pub fn router_id(&self) -> Option<IpAddr> {
        self.addresses().find(IpAddr::is_ipv4)
    }
}

async fn required(source: &dyn Metadata, path: &str) -> Result<String> {
    source.get(path).await?.map(|v| v.trim().to_string()).ok_or_else(|| Error::Backend(format!("IMDS: missing {path}")))
}

async fn lines(source: &dyn Metadata, path: &str) -> Result<Vec<String>> {
    Ok(source.get(path).await?.unwrap_or_default().lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect())
}

fn parse<T: std::str::FromStr>(values: Vec<String>, what: &str) -> Result<Vec<T>> {
    values.iter().map(|v| v.parse().map_err(|_| Error::Backend(format!("IMDS: invalid {what} {v}")))).collect()
}

pub async fn host(source: &dyn Metadata) -> Result<Host> {
    let base = "meta-data/network/interfaces/macs";
    let mut host = Host {
        instance_id: required(source, "meta-data/instance-id").await?,
        region: required(source, "meta-data/placement/region").await?,
        vpc_id: String::new(),
        vpc_cidrs: vec![],
        enis: vec![],
    };
    for mac in lines(source, &format!("{base}/")).await? {
        let mac = mac.trim_end_matches('/').to_string();
        let path = |leaf: &str| format!("{base}/{mac}/{leaf}");
        let vpc = required(source, &path("vpc-id")).await?;
        if host.vpc_id.is_empty() {
            host.vpc_id = vpc.clone();
        } else if host.vpc_id != vpc {
            // EC2 does not allow this today; refuse rather than mix route domains.
            return Err(Error::Backend(format!("IMDS: ENIs in different VPCs ({} and {vpc})", host.vpc_id)));
        }
        if host.vpc_cidrs.is_empty() {
            let mut cidrs = lines(source, &path("vpc-ipv4-cidr-blocks")).await?;
            cidrs.extend(lines(source, &path("vpc-ipv6-cidr-blocks")).await?);
            host.vpc_cidrs = parse(cidrs, "VPC CIDR")?;
        }
        let mut addresses = lines(source, &path("local-ipv4s")).await?;
        addresses.extend(lines(source, &path("ipv6s")).await?);
        host.enis.push(Eni {
            id: required(source, &path("interface-id")).await?,
            subnet_id: required(source, &path("subnet-id")).await?,
            addresses: parse(addresses, "address")?,
            mac,
        });
    }
    if host.enis.is_empty() {
        return Err(Error::Backend("IMDS: no network interfaces".into()));
    }
    // Device index order is not exposed by the MAC listing; sort for deterministic output.
    host.enis.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(host)
}

#[cfg(feature = "aws")]
pub struct Imds(aws_config::imds::Client);

#[cfg(feature = "aws")]
impl Imds {
    pub fn new() -> Self {
        Imds(aws_config::imds::Client::builder().build())
    }
}

#[cfg(feature = "aws")]
impl Default for Imds {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "aws")]
#[async_trait]
impl Metadata for Imds {
    async fn get(&self, path: &str) -> Result<Option<String>> {
        use aws_config::imds::client::error::ImdsError;
        match self.0.get(format!("/latest/{path}")).await {
            Ok(value) => Ok(Some(value.into())),
            Err(ImdsError::ErrorResponse(e)) if e.response().status().as_u16() == 404 => Ok(None),
            Err(e) => Err(Error::Backend(format!("IMDS {path}: {e}"))),
        }
    }
}
