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

use crate::api::{
    check_if_backend_svc_exists, check_if_firewall_exists, check_if_forwarding_rule_exists,
    check_if_health_check_exists, check_if_instance_group_exists,
};
use crate::constants::{
    CLEANUP_NUM_RETRIES, COMPUTE_ENDPOINT, CONTROLLER_NAME, LB_BACKEND_SVC_ANNOTATION_KEY,
    LB_FIREWALL_RULE_ANNOTATION_KEY, LB_FORWARDING_RULE_ANNOTATION_KEY, LB_HC_ANNOTATION_KEY,
    LB_IG_ANNOTATION_KEY,
};
use crate::utils::is_svc_type_lb;
use crate::{utils, Args};
use anyhow::{anyhow, Context};
use clap::Parser;
use k8s_openapi::api::core::v1::{Service, ServiceStatus};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{ListParams, Patch, PatchParams};
use kube::core::PartialObjectMetaExt;
use kube::{Api, Client, ResourceExt};
use log::debug;
use serde_json::{json, Value};
use std::borrow::BorrowMut;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub(crate) async fn delete_forwarding_rule(
    svc: &Arc<Service>,
    project: &String,
    auth_token: &String,
    region: &String,
) -> anyhow::Result<()> {
    let mut retries = CLEANUP_NUM_RETRIES;
    let annotations = svc.annotations();
    if let Some(forwarding_rule) = annotations.get(LB_FORWARDING_RULE_ANNOTATION_KEY) {
        if !check_if_forwarding_rule_exists(&project, &region, forwarding_rule).await? {
            return Ok(());
        }
        while retries != 0 {
            let res = reqwest::Client::new()
                .delete(format!(
                    "{}/compute/beta/projects/{}/regions/{}/forwardingRules/{}",
                    COMPUTE_ENDPOINT, project, region, forwarding_rule
                ))
                .bearer_auth(auth_token)
                .send()
                .await?
                .json::<Value>()
                .await?;
            if utils::wait_for_op(&project, auth_token, Some(region), None, &res).await? {
                debug!("deleted forwarding rule: {}", forwarding_rule);
                return Ok(());
            } else {
                retries = retries - 1;
                debug!(
                    "failed to delete forwarding rule: {}, retries left: {}",
                    forwarding_rule, retries
                );
            }
        }
        return Err(anyhow!(
            "failed to delete forwarding rule for service: {}/{}",
            svc.namespace().unwrap(),
            svc.name_any()
        ));
    }
    return Ok(());
}

pub(crate) async fn delete_backend_svc(
    svc: &Arc<Service>,
    project: &String,
    auth_token: &String,
    region: &String,
) -> anyhow::Result<()> {
    let mut retries = CLEANUP_NUM_RETRIES;
    let annotations = svc.annotations();
    if let Some(backend_svc) = annotations.get(LB_BACKEND_SVC_ANNOTATION_KEY) {
        if !check_if_backend_svc_exists(&project, &region, backend_svc).await? {
            return Ok(());
        }
        while retries != 0 {
            let res = reqwest::Client::new()
                .delete(format!(
                    "{}/compute/beta/projects/{}/regions/{}/backendServices/{}",
                    COMPUTE_ENDPOINT, project, region, backend_svc
                ))
                .bearer_auth(&auth_token)
                .send()
                .await?
                .json::<Value>()
                .await?;
            debug!("delete backend svc response: {:?}", res);
            if utils::wait_for_op(&project, &auth_token, Some(region), None, &res).await? {
                debug!("deleted backend svc: {}", backend_svc);
                return Ok(());
            } else {
                retries = retries - 1;
                debug!(
                    "failed to delete backend svc: {}, retries left: {}",
                    backend_svc, retries
                );
            }
        }
        return Err(anyhow!(
            "failed to delete backend svc for service: {}/{}",
            svc.namespace().unwrap(),
            svc.name_any()
        ));
    }
    return Ok(());
}

pub(crate) async fn delete_instance_groups(
    svc: &Arc<Service>,
    project: &String,
    auth_token: &String,
    k8s_client: Client,
) -> anyhow::Result<()> {
    let annotations = svc.annotations();
    let api: Api<Service> = Api::<Service>::all(k8s_client);
    let lp = ListParams::default().labels(format!("{}=reconcile", CONTROLLER_NAME).as_str());
    if let Ok(res) = api.list(&lp).await {
        if res.items.iter().any(|svc| is_svc_type_lb(svc)) {
            debug!("instance group will not be deleted since there are other loadbalancers.");
            return Ok(());
        }
    };
    if let Some(backends) = annotations.get(LB_IG_ANNOTATION_KEY) {
        let groups: HashMap<_, _> = serde_json::from_str(backends)?;
        'group_delete: for (zone, group) in groups {
            let mut retries = CLEANUP_NUM_RETRIES;
            while retries != 0 {
                if !check_if_instance_group_exists(&project, &zone, &group).await? {
                    continue 'group_delete;
                }
                let res = reqwest::Client::new()
                    .delete(format!(
                        "{}/compute/beta/projects/{}/zones/{}/instanceGroups/{}",
                        COMPUTE_ENDPOINT, project, zone, group
                    ))
                    .bearer_auth(auth_token)
                    .send()
                    .await?
                    .json::<Value>()
                    .await?;
                if utils::wait_for_op(&project, auth_token, None, Some(&zone), &res).await? {
                    debug!("deleted instance group svc: {}", group);
                    continue 'group_delete;
                } else {
                    retries = retries - 1;
                    debug!(
                        "failed to delete instance group: {}, retries left: {}",
                        group, retries
                    );
                }
            }
            return Err(anyhow!(
                "failed to delete instance groups for service: {}/{}",
                svc.namespace().unwrap(),
                svc.name_any()
            ));
        }
    }
    return Ok(());
}

pub(crate) async fn delete_health_check(
    svc: &Arc<Service>,
    project: &String,
    auth_token: &String,
    region: &String,
) -> anyhow::Result<()> {
    let mut retries = CLEANUP_NUM_RETRIES;
    let annotations = svc.annotations();
    if let Some(health_check) = annotations.get(LB_HC_ANNOTATION_KEY) {
        if !check_if_health_check_exists(&project, &region, health_check).await? {
            return Ok(());
        }
        while retries != 0 {
            let res = reqwest::Client::new()
                .delete(format!(
                    "{}/compute/beta/projects/{}/regions/{}/healthChecks/{}",
                    COMPUTE_ENDPOINT, project, region, health_check
                ))
                .bearer_auth(auth_token)
                .send()
                .await?
                .json::<Value>()
                .await?;
            if utils::wait_for_op(&project, auth_token, Some(region), None, &res).await? {
                debug!("deleted health check: {}", health_check);
                return Ok(());
            } else {
                retries = retries - 1;
                debug!(
                    "failed to delete health check: {}, retries left: {}",
                    health_check, retries
                );
            }
        }
        return Err(anyhow!(
            "failed to delete health check for service: {}/{}",
            svc.namespace().unwrap(),
            svc.name_any()
        ));
    }
    return Ok(());
}

pub(crate) async fn delete_firewall(
    svc: &Arc<Service>,
    project: &String,
    auth_token: &String,
) -> anyhow::Result<()> {
    let mut retries = CLEANUP_NUM_RETRIES;
    let args = Args::parse();
    let shared_vpc_project_id = args.shared_vpc_project_id;
    let project = if !shared_vpc_project_id.is_empty() {
        &shared_vpc_project_id
    } else {
        project
    };
    let annotations = svc.annotations();
    if let Some(fw) = annotations.get(LB_FIREWALL_RULE_ANNOTATION_KEY) {
        if !check_if_firewall_exists(project, fw).await? {
            return Ok(());
        }
        while retries != 0 {
            let res = reqwest::Client::new()
                .delete(format!(
                    "{}/compute/beta/projects/{}/global/firewalls/{}",
                    COMPUTE_ENDPOINT, project, fw
                ))
                .bearer_auth(auth_token)
                .send()
                .await?
                .json::<Value>()
                .await?;
            if utils::wait_for_op(project, auth_token, None, None, &res).await? {
                debug!("deleted firewall: {}", fw);
                return Ok(());
            } else {
                retries = retries - 1;
                debug!(
                    "failed to delete firewall: {}, retries left: {}",
                    fw, retries
                );
            }
        }
        return Err(anyhow!(
            "failed to delete firewall for service: {}/{}",
            svc.namespace().unwrap(),
            svc.name_any()
        ));
    }
    return Ok(());
}

pub(crate) async fn reset_svc(svc: &Arc<Service>, k8s_client: &Client) -> anyhow::Result<()> {
    let service_name = &svc.name_any();
    let service_ns = &svc.namespace().unwrap();
    let api: Api<Service> = Api::<Service>::namespaced(k8s_client.to_owned(), service_ns);
    if !is_svc_type_lb(svc) {
        let status = ServiceStatus {
            load_balancer: None,
            ..Default::default()
        };
        let data = json!({"status": status});
        let svc_updated = api
            .patch_status(service_name, &PatchParams::default(), &Patch::Merge(data))
            .await
            .with_context(|| {
                format!(
                    "failed to reset lb status for service: {}/{}",
                    service_ns, service_name
                )
            })?;
        debug!(
            "lb status reset complete for service: {}/{} status: {:?}",
            service_ns, service_name, svc_updated.status
        );
    }
    let mut updated = BTreeMap::new();
    if let Some(mut data) = svc.metadata.annotations.to_owned() {
        updated.append(data.borrow_mut());
    }
    let remove_annotations = vec![
        LB_FORWARDING_RULE_ANNOTATION_KEY,
        LB_BACKEND_SVC_ANNOTATION_KEY,
        LB_IG_ANNOTATION_KEY,
        LB_HC_ANNOTATION_KEY,
        LB_FIREWALL_RULE_ANNOTATION_KEY,
    ];
    remove_annotations.iter().for_each(|&r| {
        updated.remove(r);
    });
    let metadata = ObjectMeta {
        annotations: Some(updated),
        ..Default::default()
    }
    .into_request_partial::<Service>();
    api.patch_metadata(
        service_name,
        &PatchParams::apply("annotate"),
        &Patch::Apply(&metadata),
    )
    .await
    .with_context(|| {
        format!(
            "failed to cleanup lb annotations for service: {}/{}",
            service_ns, service_name
        )
    })?;
    Ok(())
}
