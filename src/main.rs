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

#![feature(fs_try_exists)]
#![feature(async_closure)]
#![feature(slice_take)]

mod api;
mod cleanup;
mod constants;
mod controller;
mod errors;
mod gcp_auth;
mod utils;

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
}
