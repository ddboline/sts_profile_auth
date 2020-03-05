#![allow(unused_imports)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::similar_names)]
#![allow(clippy::shadow_unrelated)]
#![allow(clippy::pub_enum_variant_names)]
#![allow(clippy::missing_errors_doc)]

//! This crate extends [Rusoto's](https://crates.io/crates/rusoto) existing authentication infrastructure to support this feature.

use dirs::home_dir;
use lazy_static::lazy_static;
use regex::Regex;
use rusoto_core::{request::TlsError, Client, HttpClient, Region, RusotoError};
use rusoto_credential::{AutoRefreshingProvider, CredentialsError, StaticProvider};
use rusoto_sts::{StsAssumeRoleSessionCredentialsProvider, StsClient};
use std::{
    collections::HashMap,
    env::{var, var_os, VarError},
    fmt::Display,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};
use thiserror::Error;

lazy_static! {
    static ref PROFILE_REGEX: Regex =
        Regex::new(r"^\[(profile )?([^\]]+)\]$").expect("Failed to compile regex");
}

type StsAuthProvider = AutoRefreshingProvider<StsAssumeRoleSessionCredentialsProvider>;

fn get_sts_auth_provider(
    client: StsClient,
    role_arn: &str,
) -> Result<StsAuthProvider, StsClientError> {
    let provider = StsAssumeRoleSessionCredentialsProvider::new(
        client,
        role_arn.to_string(),
        "default".to_string(),
        None,
        None,
        None,
        None,
    );
    AutoRefreshingProvider::new(provider).map_err(Into::into)
}

#[derive(Debug, Error)]
pub enum StsClientError {
    #[error("HttpClient init failed")]
    TlsError(#[from] TlsError),
    #[error("Profile {0} is not available")]
    StsProfileError(String),
    #[error("No HOME directory")]
    NoHomeError,
    #[error("Error obtaining STS Credentials {0}")]
    CredentialsError(#[from] CredentialsError),
    #[error("RusotoError {0}")]
    RusotoError(String),
}

impl<T: std::error::Error + 'static> From<RusotoError<T>> for StsClientError {
    fn from(item: RusotoError<T>) -> Self {
        Self::RusotoError(item.to_string())
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! get_client_sts_region_profile {
    ($T:ty, $region:expr, $profile:expr) => {
        $crate::StsInstance::new($profile).and_then(|sts| {
            let client = sts.get_client()?;
            let region = if let Some(r) = $region {
                r
            } else {
                sts.get_region()
            };
            Ok(<$T>::new_with_client(client, region))
        })
    };
}

/// Macro to return a profile authenticated client
///
/// This macro takes two arguments:
/// 1. A Rusoto client type (e.g. Ec2Client) which has the `new_with_client` method
/// 2. A Rusoto Region (optional)
/// 3. A Profile Name (optional)
///
/// It will return an instance of the provided client (e.g. Ec2Client) which will use
/// either the default profile or the profile specified by the AWS_PROFILE env variable
/// when authenticating.
///
/// The macro `get_client_sts_with_profile` accepts a client and a profile name but no region.
///
/// # Example usage:
/// ``` ignore
/// use rusoto_core::Region;
/// use rusoto_ec2::Ec2Client;
/// use sts_profile_auth::get_client_sts;
/// use sts_profile_auth::StsClientError;
///
/// # fn main() -> Result<(), StsClientError> {
/// let ec2 = get_client_sts!(Ec2Client)?;
/// let ec2 = get_client_sts!(Ec2Client, Region::default())?;
/// let ec2 = get_client_sts!(Ec2Client, Region::default(), "default")?;
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! get_client_sts {
    ($T:ty) => {
        $crate::get_client_sts_region_profile!($T, None, None)
    };
    ($T:ty, $region:expr) => {
        $crate::get_client_sts_region_profile!($T, Some($region), None)
    };
    ($T:ty, $region:expr, $profile:expr) => {
        $crate::get_client_sts_region_profile!($T, Some($region), Some($profile))
    };
}

/// Macro to return a profile authenticated client
///
/// This macro takes two arguments:
/// 1. A Rusoto client type (e.g. Ec2Client) which has the `new_with_client` method
/// 2. A Profile Name
///
/// It will return an instance of the provided client (e.g. Ec2Client) which will use
/// the specified profile when authenticating.
///
/// # Example usage:
/// ``` ignore
/// use rusoto_core::Region;
/// use rusoto_ec2::Ec2Client;
/// use sts_profile_auth::get_client_sts_with_profile;
/// use sts_profile_auth::StsClientError;
///
/// # fn main() -> Result<(), StsClientError> {
/// let ec2 = get_client_sts_with_profile!(Ec2Client, "default")?;
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! get_client_sts_with_profile {
    ($T:ty, $profile:expr) => {
        $crate::get_client_sts_region_profile!($T, None, Some($profile))
    };
}

/// `StsInstance` contains an `StsClient` instance, and metadata used to create it (region, keys, role arn)
#[derive(Clone)]
pub struct StsInstance {
    sts_client: StsClient,
    region: Region,
    aws_access_key_id: String,
    aws_secret_access_key: String,
    role_arn: Option<String>,
}

impl Default for StsInstance {
    fn default() -> Self {
        Self {
            sts_client: StsClient::new(Region::default()),
            region: Region::default(),
            aws_access_key_id: "".to_string(),
            aws_secret_access_key: "".to_string(),
            role_arn: None,
        }
    }
}

impl StsInstance {
    /// Create a new `StsInstance`, either specifying a profile name, using the `AWS_PROFILE` environment variable, or using default
    pub fn new(profile_name: Option<&str>) -> Result<Self, StsClientError> {
        let profiles = AwsProfileInfo::fill_profile_map()?;
        let profile_name = match profile_name {
            Some(n) => n.to_string(),
            None => var("AWS_PROFILE")
                .ok()
                .unwrap_or_else(|| "default".to_string()),
        };
        let current_profile = profiles
            .get(&profile_name)
            .ok_or_else(|| StsClientError::StsProfileError(profile_name))?;

        let region: Region = current_profile
            .region
            .parse()
            .ok()
            .unwrap_or_default();
        let (key, secret) = match current_profile.source_profile.as_ref() {
            Some(prof) => {
                let source_profile = profiles
                    .get(prof)
                    .ok_or_else(|| StsClientError::StsProfileError(prof.to_string()))?;
                (
                    source_profile.aws_access_key_id.to_string(),
                    source_profile.aws_secret_access_key.to_string(),
                )
            }
            None => (
                current_profile.aws_access_key_id.to_string(),
                current_profile.aws_secret_access_key.to_string(),
            ),
        };
        let provider = StaticProvider::new_minimal(key.to_string(), secret.to_string());

        Ok(Self {
            sts_client: StsClient::new_with(HttpClient::new()?, provider, region.clone()),
            region,
            aws_access_key_id: key,
            aws_secret_access_key: secret,
            role_arn: current_profile.role_arn.clone(),
        })
    }

    /// Get an auto-refreshing credential provider
    pub fn get_provider(&self) -> Result<Option<StsAuthProvider>, StsClientError> {
        match &self.role_arn {
            Some(role_arn) => {
                let provider = get_sts_auth_provider(self.sts_client.clone(), role_arn)?;
                Ok(Some(provider))
            }
            None => Ok(None),
        }
    }

    /// Get an instance of `rusoto_core::Client` which can be used to instantiate any other rusoto client type.
    pub fn get_client(&self) -> Result<Client, StsClientError> {
        let client = match self.get_provider()? {
            Some(provider) => Client::new_with(provider, rusoto_core::HttpClient::new()?),
            None => Client::shared(),
        };
        Ok(client)
    }

    pub fn get_region(&self) -> Region {
        self.region.clone()
    }
}

/// Profile meta-data, representing either a profile with an access key, or a profile utilizing sts.
#[derive(Default, Clone, Debug)]
pub struct AwsProfileInfo {
    pub name: String,
    pub region: String,
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub role_arn: Option<String>,
    pub source_profile: Option<String>,
}

impl AwsProfileInfo {
    /// This function fills an instance of `AwsProfileInfo` using a hashmap generated by `fill_profile_map`
    /// It will return None if all required information cannot be found.
    pub fn from_hashmap(
        profile_name: &str,
        profile_map: &HashMap<String, HashMap<String, String>>,
    ) -> Option<Self> {
        let name = profile_name.to_string();
        let prof_map = match profile_map.get(profile_name) {
            Some(p) => p,
            None => return None,
        };
        let region = prof_map
            .get("region")
            .cloned()
            .unwrap_or_else(|| "us-east-1".to_string());

        let source_profile = prof_map.get("source_profile").map(ToString::to_string);
        let role_arn = prof_map.get("role_arn").map(ToString::to_string);
        let mut access_key = prof_map.get("aws_access_key_id").map(ToString::to_string);
        let mut access_secret = prof_map
            .get("aws_secret_access_key")
            .map(ToString::to_string);

        if let Some(s) = source_profile.as_ref() {
            let pmap = match profile_map.get(s) {
                Some(p) => p,
                None => return None,
            };
            pmap.get("aws_access_key_id")
                .map(|a| access_key.replace(a.to_string()));
            pmap.get("aws_secret_access_key")
                .map(|a| access_secret.replace(a.to_string()));
        }
        let aws_access_key_id = match access_key {
            Some(a) => a,
            None => return None,
        };
        let aws_secret_access_key = match access_secret {
            Some(a) => a,
            None => return None,
        };
        Some(Self {
            name,
            region,
            aws_access_key_id,
            aws_secret_access_key,
            role_arn,
            source_profile,
        })
    }

    /// Extract profile information hashmap from `${HOME}/.aws/config` and `${HOME}/.aws/credentials`
    pub fn fill_profile_map() -> Result<HashMap<String, Self>, StsClientError> {
        let config_dir = if let Some(s) = var_os("AWS_CONFIG_FILE") {
            PathBuf::from(s)
        } else if let Some(h) = home_dir() {
            h.join(".aws")
        } else {
            return Err(StsClientError::NoHomeError);
        };

        let config_file = config_dir.join("config");
        let credential_file = config_dir.join("credentials");

        let mut profile_map: HashMap<String, HashMap<String, String>> = HashMap::new();

        for fname in &[config_file, credential_file] {
            if !Path::new(fname).exists() {
                continue;
            }

            if let Some(p) = parse_config_file(fname) {
                if profile_map.is_empty() {
                    profile_map = p;
                } else {
                    for (k, v) in p {
                        if let Some(pm) = profile_map.get_mut(&k) {
                            for (k_, v_) in v {
                                pm.insert(k_, v_);
                            }
                        } else {
                            profile_map.insert(k, v);
                        }
                    }
                }
            }
        }
        let profile_map: HashMap<_, _> = profile_map
            .keys()
            .filter_map(|k| Self::from_hashmap(k, &profile_map).map(|p| (k.to_string(), p)))
            .collect();

        Ok(profile_map)
    }
}

/// Stolen from rusoto credential's profile.rs
/// Parses an aws credentials config file and returns a hashmap of hashmaps.
fn parse_config_file<P>(file_path: P) -> Option<HashMap<String, HashMap<String, String>>>
where
    P: AsRef<Path>,
{
    if !file_path.as_ref().exists() || !file_path.as_ref().is_file() {
        return None;
    }

    let file = File::open(file_path).expect("expected file");
    let file_lines = BufReader::new(&file);
    let result: (HashMap<String, HashMap<String, String>>, Option<String>) = file_lines
        .lines()
        .filter_map(|line| {
            line.ok()
                .map(|l| l.trim_matches(' ').to_owned())
                .into_iter()
                .find(|l| !l.starts_with('#') && !l.is_empty())
        })
        .fold(Default::default(), |(mut result, profile), line| {
            if PROFILE_REGEX.is_match(&line) {
                let caps = PROFILE_REGEX.captures(&line).unwrap();
                let next_profile = caps.get(2).map(|value| value.as_str().to_string());
                (result, next_profile)
            } else {
                match &line
                    .splitn(2, '=')
                    .map(|value| value.trim_matches(' '))
                    .collect::<Vec<&str>>()[..]
                {
                    [key, value] if !key.is_empty() && !value.is_empty() => {
                        if let Some(current) = profile.clone() {
                            let values = result.entry(current).or_insert_with(HashMap::new);
                            (*values).insert((*key).to_string(), (*value).to_string());
                        }
                        (result, profile)
                    }
                    _ => (result, profile),
                }
            }
        });
    Some(result.0)
}

#[cfg(test)]
mod tests {
    use rusoto_core::Region;
    use rusoto_ec2::{DescribeInstancesRequest, Ec2, Ec2Client};

    use crate::{AwsProfileInfo, StsClientError};

    #[test]
    #[ignore]
    fn test_fill_profile_map() -> Result<(), StsClientError> {
        let prof_map = AwsProfileInfo::fill_profile_map()?;
        for (k, v) in &prof_map {
            println!("{} {:?}", k, v);
        }
        assert!(prof_map.len() > 0);
        assert!(prof_map.contains_key("default"));
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_client_sts() -> Result<(), StsClientError> {
        let ec2 = get_client_sts!(Ec2Client)?;
        let instances: Vec<_> = ec2
            .describe_instances(DescribeInstancesRequest::default())
            .await
            .map(|instances| {
                instances
                    .reservations
                    .unwrap_or_else(Vec::new)
                    .into_iter()
                    .filter_map(|res| {
                        res.instances.map(|instances| {
                            instances
                                .into_iter()
                                .filter_map(|inst| inst.instance_id)
                                .collect::<Vec<_>>()
                        })
                    })
                    .flatten()
                    .collect()
            })?;
        println!("{:?}", instances);
        assert!(instances.len() > 0);
        Ok(())
    }
}
