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

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::Event;
use kube::runtime::watcher::Config;
use kube::runtime::{
    finalizer, predicates, reflector, watcher, Controller, Predicate, WatchStreamExt,
};
use kube::{Api, Client, ResourceExt};
use log::{debug, info, warn};

use crate::constants::{CONTROLLER_NAME, LB_BACKEND_SVC_ANNOTATION_KEY};
use crate::errors::Error::{ControllerError, FinalizerError};
use crate::errors::{Error, Result};
use crate::{api, cleanup, gcp_auth, utils, Ctx, State};

pub async fn run(state: State) -> anyhow::Result<()> {
    info!("starting GCP load balancer controller....");
    let client = Client::try_default()
        .await
        .expect("failed to create k8s client.");
    let api = Api::<Service>::all(client.clone());
    let (reader, writer) = reflector::store();
    let wc = Config::default().labels(format!("{}=reconcile", CONTROLLER_NAME).as_str());
    let changes = watcher(api, wc)
        .reflect(writer)
        .touched_objects()
        .predicate_filter(
            predicates::generation
                .combine(predicates::labels)
                .combine(predicates::annotations)
                .combine(predicates::resource_version),
        );
    Controller::for_stream(changes, reader)
        .shutdown_on_signal()
        .run(reconcile, error_policy, state.to_context(client))
        .filter_map(|x| async move { Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}

async fn reconcile(svc: Arc<Service>, ctx: Arc<Ctx>) -> Result<Action> {
    let client = ctx.client.clone();
    let namespace = &svc.namespace().unwrap();
    let api = Api::<Service>::namespaced(client, namespace);

    if !(utils::is_svc_type_lb(svc.as_ref()) || svc.metadata.deletion_timestamp.is_some()) {
        return if utils::check_if_lb_annotations_exist_on_svc(svc.as_ref()) {
            debug!(
                "service type updated, running lb cleanup: {}/{}",
                svc.namespace().unwrap(),
                svc.name_any()
            );
            cleanup(svc, ctx).await
        } else {
            debug!("no update required");
            Ok(Action::await_change())
        };
    }

    finalizer(
        &api,
        format!("{}/cleanup", CONTROLLER_NAME).as_str(),
        svc,
        |event| async {
            match event {
                Event::Apply(svc) => create(svc, ctx).await,
                Event::Cleanup(svc) => cleanup(svc, ctx).await,
            }
        },
    )
    .await
    .map_err(|e| FinalizerError(Box::new(e)))
}

async fn create(svc: Arc<Service>, ctx: Arc<Ctx>) -> Result<Action> {
    let service_ns = &svc.namespace().unwrap();
    let service_name = &svc.name_any();
    let annotations = &svc.metadata.annotations;
    if let Some(data) = annotations {
        info!(
            "creating loadbalancer for service: {}/{}",
            service_ns, service_name
        );
        let region = &gcp_auth::get_region().await?;
        api::process_instance_groups(&svc, region, data, &ctx.client.clone())
            .await
            .map_err(ControllerError)?;

        api::process_health_checks(&svc, region, data, &ctx.client.clone())
            .await
            .map_err(ControllerError)?;

        if let Err(_) = utils::check_backend_svc_prerequisites(service_name, service_ns, data) {
            debug!(
                "waiting for health check and instance groups for service: {}/{}",
                service_ns, service_name
            );
            return Ok(Action::requeue(Duration::from_secs(10)));
        }
        api::process_backend_service(&svc, region, data, &ctx.client.clone())
            .await
            .map_err(ControllerError)?;

        if let Err(_) = utils::check_resource_prerequisites(
            service_name,
            service_ns,
            data,
            vec![LB_BACKEND_SVC_ANNOTATION_KEY],
        ) {
            debug!(
                "waiting for backends for service: {}/{}",
                service_ns, service_name
            );
            return Ok(Action::requeue(Duration::from_secs(10)));
        }
        api::process_forwarding_rule(&svc, region, data, &ctx.client.clone())
            .await
            .map_err(ControllerError)?;
        info!(
            "ensured loadbalancer for service: {}/{}",
            service_ns, service_name
        );
    }
    Ok(Action::await_change())
}

pub(crate) async fn cleanup(svc: Arc<Service>, ctx: Arc<Ctx>) -> Result<Action> {
    let service_ns = &svc.namespace().unwrap();
    let service_name = &svc.name_any();
    let project = gcp_auth::get_project_id().await?;
    let region = gcp_auth::get_region().await?;
    if utils::check_if_lb_annotations_exist_on_svc(svc.as_ref()) {
        info!(
            "deleting loadbalancer for service: {}/{}",
            service_ns, service_name
        );
        let auth_token = gcp_auth::get_access_token().await?;
        cleanup::delete_forwarding_rule(&svc, &project, &auth_token, &region).await?;
        cleanup::delete_backend_svc(&svc, &project, &auth_token, &region).await?;
        cleanup::delete_instance_groups(&svc, &project, &auth_token, ctx.client.clone()).await?;
        cleanup::delete_health_check(&svc, &project, &auth_token, &region).await?;
        cleanup::delete_firewall(&svc, &project, &auth_token).await?;
        cleanup::reset_svc(&svc, &ctx.client.clone()).await?;
        info!(
            "deleted loadbalancer for service: {}/{}",
            service_ns, service_name
        );
    }
    Ok(Action::await_change())
}

fn error_policy(_svc: Arc<Service>, err: &Error, _ctx: Arc<Ctx>) -> Action {
    warn!("reconcile failed: {:?}", err);
    Action::requeue(Duration::from_secs(10))
}
