use failure::format_err;
use lazy_static::lazy_static;
use regex::Regex;
use rusoto_core::{HttpClient, Region};
use rusoto_credential::{AutoRefreshingProvider, StaticProvider};
use rusoto_ec2::Ec2Client;
use rusoto_ecr::EcrClient;
use rusoto_sts::{StsAssumeRoleSessionCredentialsProvider, StsClient};
use std::collections::HashMap;
use std::env::var;
use std::error::Error as StdError;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

lazy_static! {
    static ref PROFILE_REGEX: Regex =
        Regex::new(r"^\[(profile )?([^\]]+)\]$").expect("Failed to compile regex");
}

macro_rules! get_client_sts {
    ($T:ty, $region:expr) => {
        StsInstance::new(None).and_then(|sts| {
            let client = match sts.get_provider() {
                Some(provider) => <$T>::new_with(HttpClient::new()?, provider, $region),
                None => <$T>::new($region),
            };
            Ok(client)
        })
    };
}

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
            sts_client: StsClient::new(Region::UsEast1),
            region: Region::UsEast1,
            aws_access_key_id: "".to_string(),
            aws_secret_access_key: "".to_string(),
            role_arn: None,
        }
    }
}

impl StsInstance {
    pub fn new(profile_name: Option<&str>) -> Result<Self, Box<dyn StdError + Send>> {
        let profiles = AwsProfileInfo::fill_profile_map()?;
        let profile_name = match profile_name {
            Some(n) => n.to_string(),
            None => var("AWS_PROFILE")
                .ok()
                .unwrap_or_else(|| "default".to_string()),
        };
        let current_profile = profiles
            .get(&profile_name)
            .ok_or_else(|| format_err!("No such profile: {}", profile_name))?;

        let region = current_profile
            .region
            .parse()
            .ok()
            .unwrap_or(Region::UsEast1);
        let (key, secret) = match current_profile.source_profile.as_ref() {
            Some(prof) => {
                let source_profile = profiles
                    .get(prof)
                    .ok_or_else(|| format_err!("Source profile {} doesn't exist", prof))?;
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

    pub fn get_provider(
        &self,
    ) -> Option<AutoRefreshingProvider<StsAssumeRoleSessionCredentialsProvider>> {
        self.role_arn.as_ref().and_then(|role_arn| {
            AutoRefreshingProvider::new(StsAssumeRoleSessionCredentialsProvider::new(
                self.sts_client.clone(),
                role_arn.to_string(),
                "default".to_string(),
                None,
                None,
                None,
                None,
            ))
            .ok()
        })
    }

    pub fn get_ec2_client(&self, region: Region) -> Result<Ec2Client, Box<dyn StdError + Send>> {
        get_client_sts!(Ec2Client, region)
    }

    pub fn get_ecr_client(&self, region: Region) -> Result<EcrClient, Box<dyn StdError + Send>> {
        get_client_sts!(EcrClient, region)
    }
}

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
    pub fn from_hashmap(
        profile_name: &str,
        profile_map: &HashMap<String, HashMap<String, String>>,
    ) -> Option<AwsProfileInfo> {
        let name = profile_name.to_string();
        let prof_map = match profile_map.get(profile_name) {
            Some(p) => p,
            None => return None,
        };
        let region = prof_map
            .get("region")
            .cloned()
            .unwrap_or_else(|| "us-east-1".to_string());

        let source_profile = prof_map.get("source_profile").map(|x| x.to_string());
        let role_arn = prof_map.get("role_arn").map(|x| x.to_string());
        let mut access_key = prof_map.get("aws_access_key_id").map(|x| x.to_string());
        let mut access_secret = prof_map.get("aws_secret_access_key").map(|x| x.to_string());

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
        Some(AwsProfileInfo {
            name,
            region,
            aws_access_key_id,
            aws_secret_access_key,
            role_arn,
            source_profile,
        })
    }

    pub fn fill_profile_map() -> Result<HashMap<String, AwsProfileInfo>, Box<dyn StdError + Send>> {
        let home_dir = var("HOME").map_err(|e| format_err!("No HOME directory {}", e))?;
        let config_file = format!("{}/.aws/config", home_dir);
        let credential_file = format!("{}/.aws/credentials", home_dir);

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
                        match profile_map.get_mut(&k) {
                            Some(pm) => {
                                for (k_, v_) in v {
                                    pm.insert(k_, v_);
                                }
                            }
                            None => {
                                profile_map.insert(k, v);
                            }
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
    use crate::sts_instance::AwsProfileInfo;

    #[test]
    #[ignore]
    fn test_fill_profile_map() {
        let prof_map = AwsProfileInfo::fill_profile_map().unwrap();
        for (k, v) in &prof_map {
            println!("{} {:?}", k, v);
        }
        assert!(prof_map.len() > 0);
        assert!(prof_map.contains_key("default"));
    }
}
