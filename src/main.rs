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

#![feature(async_closure)]
#![feature(slice_take)]

mod api;
mod cleanup;
mod constants;
mod controller;
mod errors;
mod gcp_auth;
mod ownership;
mod urls;
mod utils;
mod validation;

use anyhow::Context;
use clap::Parser;
use env_logger::Env;
use kube::Client;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    let args = Args::parse();
    validation::InstanceGroupAllowlist::parse(&args.allowed_instance_groups)?;

    let state = State::default();
    tokio::try_join!(controller::run(state.clone()))
        .with_context(|| "error occurred running the controller")?;

    Ok(())
}

#[derive(Clone, Default)]
pub struct State {}

impl State {
    pub fn to_context(&self, client: Client) -> Arc<Ctx> {
        Arc::new(Ctx { client })
    }
}

#[derive(Clone)]
pub struct Ctx {
    pub client: Client,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub(crate) struct Args {
    #[arg(long, default_value = "")]
    pub(crate) region: String,
    #[arg(long, default_value = "")]
    pub(crate) project_id: String,
    #[arg(long)]
    pub(crate) network: String,
    #[arg(long, default_value = "")]
    pub(crate) shared_vpc_project_id: String,
    /// Instance groups Services may select with the zonal-migs / regional-migs annotations, as
    /// comma separated <namespace>/<location>/<group> entries (<namespace> may be *).
    #[arg(long, value_delimiter = ',')]
    pub(crate) allowed_instance_groups: Vec<String>,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Args;

    #[test]
    fn args_parses_allowed_instance_groups_and_defaults_to_empty() {
        let default_args = Args::try_parse_from(["gcp-lb-controller-rs", "--network", "default"])
            .expect("default args should parse");
        assert!(default_args.allowed_instance_groups.is_empty());

        let with_allowlist = Args::try_parse_from([
            "gcp-lb-controller-rs",
            "--network",
            "default",
            "--allowed-instance-groups",
            "a/b/c,d/e/f",
        ])
        .expect("allowlist args should parse");
        assert_eq!(
            with_allowlist.allowed_instance_groups,
            vec!["a/b/c".to_string(), "d/e/f".to_string()]
        );
    }
}
