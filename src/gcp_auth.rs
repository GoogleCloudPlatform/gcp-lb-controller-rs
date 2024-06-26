// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::anyhow;
use clap::Parser;
use log::debug;
use std::fs;
use std::path::Path;

use crate::constants::CREDENTIALS_FILE;
use crate::{constants, Args};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AccessTokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    token_type: String,
}

pub async fn get_access_token() -> anyhow::Result<String> {
    let home = std::env::var("HOME").expect("couldn't find HOME.");
    if fs::exists(format!("{}/{}", home, CREDENTIALS_FILE))? {
        debug!("using user credentials");
        fetch_user_access_token().await
    } else {
        debug!("fetching credentials from metadata server");
        Ok(reqwest::Client::new()
            .get(constants::DEFAULT_TOKEN_URI)
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .json::<AccessTokenResponse>()
            .await?
            .access_token)
    }
}

pub(crate) async fn get_project_id() -> anyhow::Result<String> {
    let args = Args::parse();
    if &args.project_id != "" {
        return Ok(args.project_id);
    }
    Ok(reqwest::Client::new()
        .get(constants::PROJECT_ID_URI)
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .text()
        .await?)
}

pub async fn get_region() -> anyhow::Result<String> {
    debug!("fetching zone from metadata server");
    let args = Args::parse();
    if &args.region != "" {
        return Ok(args.region);
    }
    let zone = reqwest::Client::new()
        .get(constants::INSTANCE_ZONE_URI)
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .text()
        .await?;
    let re = Regex::new(r"^(projects/\d+/zones/(?P<region>.*)-[a-z])$").unwrap();
    let caps = re.captures(zone.as_str());
    match caps {
        Some(caps) => Ok(String::from(&caps["region"])),
        None => Err(anyhow!(
            "error occurred fetching region from zone: {}",
            zone
        )),
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct RefreshTokenRequest {
    client_id: String,
    client_secret: String,
    #[serde(rename(deserialize = "type"))]
    grant_type: String,
    refresh_token: String,
}

pub(crate) async fn fetch_user_access_token() -> anyhow::Result<String> {
    let mut payload: RefreshTokenRequest = serde_json::from_str(&fs::read_to_string(
        Path::new(env!("HOME")).join(CREDENTIALS_FILE),
    )?)?;
    payload.grant_type = String::from("refresh_token");
    Ok(reqwest::Client::new()
        .post(constants::GCP_TOKEN_URI)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&payload)?)
        .send()
        .await?
        .json::<AccessTokenResponse>()
        .await?
        .access_token)
}
