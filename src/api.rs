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

use anyhow::{anyhow, Context};
use clap::Parser;
use k8s_openapi::api::core::v1::Service;
use kube::{Client, ResourceExt};
use log::debug;
use reqwest::header::ACCEPT;
use serde_json::{json, Value};
use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::cleanup::delete_forwarding_rule;
use crate::constants::{
    LB_BACKEND_SVC_ANNOTATION_KEY, LB_FIREWALL_RULE_ANNOTATION_KEY,
    LB_FORWARDING_RULE_ANNOTATION_KEY, LB_HC_ANNOTATION_KEY, LB_HC_PORT_ANNOTATION_KEY,
    LB_IG_ANNOTATION_KEY, LB_REGIONAL_MIG_ANNOTATION_KEY, LB_STATIC_IP_ANNOTATION_KEY,
    LB_ZONAL_MIG_ANNOTATION_KEY,
};
use crate::errors::Error::ControllerError;
use crate::ownership::Owner;
use crate::{gcp_auth, ownership, urls, utils, validation, Args};

pub(crate) async fn create_tcp_hc(
    service_name: &String,
    service_ns: &String,
    port: i32,
    region: &String,
    hc_name: Option<&String>,
    firewall_rule: Option<&String>,
    k8s_client: &Client,
) -> anyhow::Result<()> {
    let project = gcp_auth::get_project_id().await?;
    let auth_token = gcp_auth::get_access_token().await?;
    let description = ownership::ownership_marker(service_ns, service_name);

    if let Some(firewall_rule) = firewall_rule {
        debug!(
            "firewall rule annotation exists, updating: {}",
            firewall_rule
        );
        update_firewall_rule(
            firewall_rule,
            &description,
            service_name,
            service_ns,
            vec![port],
            k8s_client,
        )
        .await?;
    } else {
        create_firewall_rule(
            service_name,
            service_ns,
            vec![port],
            &description,
            k8s_client,
        )
        .await?;
    }

    if let Some(hc_name) = hc_name {
        debug!("health check annotation exists, updating: {}", hc_name);
        verify_and_update_hc(
            hc_name,
            service_name,
            service_ns,
            port,
            region,
            &description,
            k8s_client,
        )
        .await?;
    } else {
        let res = reqwest::Client::new()
            .post(urls::compute_url(&[
                "compute",
                "v1",
                "projects",
                &project,
                "regions",
                region,
                "healthChecks",
            ])?)
            .header(ACCEPT, "application/json")
            .bearer_auth(&auth_token)
            .json(&json!({
            "name": format!("tcp-hc-{}-{}-{}-{}", service_ns, service_name, port, utils::random_string()),
            "description": description,
            "region": region,
            "type": "TCP",
            "tcpHealthCheck": {
                "port": port,
                "portSpecification": "GCE_VM_IP_PORT"
            }
        }))
            .send()
            .await?
            .json::<Value>()
            .await?;
        return if utils::wait_for_op(&project, &auth_token, Some(region), None, &res).await? {
            debug!("health check creation operation status: {}", res["status"]);
            let svc = utils::get_svc(service_name, service_ns, k8s_client).await?;
            let target_link = res["targetLink"].as_str().unwrap();
            utils::annotate_svc(
                &svc,
                LB_HC_ANNOTATION_KEY,
                &utils::get_hc_name_from_target_link(target_link)?,
                k8s_client,
            )
            .await?;
            Ok(())
        } else {
            Err(anyhow!(
                "error occurred creating tcp health check for svc: {} error: {:?}",
                service_name,
                res["statusMessage"].as_str()
            ))
        };
    }
    Ok(())
}

pub(crate) async fn process_health_checks(
    svc: &Arc<Service>,
    region: &String,
    svc_annotations: &BTreeMap<String, String>,
    k8s_client: &Client,
) -> anyhow::Result<()> {
    let service_name = &svc.name_any();
    let service_ns = &svc.namespace().unwrap();

    let hc_name = validation::resource_name_annotation(svc_annotations, LB_HC_ANNOTATION_KEY)?;
    let firewall_rule =
        validation::resource_name_annotation(svc_annotations, LB_FIREWALL_RULE_ANNOTATION_KEY)?;

    if svc_annotations.contains_key(LB_HC_PORT_ANNOTATION_KEY) {
        if let Some(port) = svc_annotations.get(LB_HC_PORT_ANNOTATION_KEY) {
            let port = port.parse().map_err(|err| {
                anyhow!(
                    "invalid {} {}: expected valid port integer ({})",
                    LB_HC_PORT_ANNOTATION_KEY,
                    validation::display_untrusted(port),
                    err
                )
            })?;
            let node_port = utils::get_node_port(port, &svc)?;
            create_tcp_hc(
                service_name,
                service_ns,
                node_port,
                region,
                hc_name,
                firewall_rule,
                k8s_client,
            )
            .await?;
        }
    } else {
        debug!(
            "no health check port provided in the annotation: {} \
        using the first port in service: {}/{}",
            LB_HC_PORT_ANNOTATION_KEY, service_ns, service_name
        );
        if let Some(spec) = &svc.spec {
            if let Some(ports) = &spec.ports {
                if let Some(sp) = ports.first() {
                    let node_port = utils::get_node_port(sp.port, &svc)?;
                    create_tcp_hc(
                        service_name,
                        service_ns,
                        node_port,
                        region,
                        hc_name,
                        firewall_rule,
                        k8s_client,
                    )
                    .await?;
                }
            }
        }
    }
    Ok(())
}

async fn verify_and_update_hc(
    hc_name: &String,
    svc_name: &String,
    svc_ns: &String,
    hc_port: i32,
    region: &String,
    description: &String,
    k8s_client: &Client,
) -> anyhow::Result<()> {
    let project = gcp_auth::get_project_id().await?;
    let auth_token = gcp_auth::get_access_token().await?;

    let url = urls::compute_url(&[
        "compute",
        "v1",
        "projects",
        &project,
        "regions",
        region,
        "healthChecks",
        hc_name,
    ])?;
    ownership::require_owned_resource(
        &url,
        &auth_token,
        Owner::Service {
            namespace: svc_ns,
            name: svc_name,
        },
        LB_HC_ANNOTATION_KEY,
    )
    .await?;
    let res = reqwest::Client::new()
        .put(&url)
        .header(ACCEPT, "application/json")
        .bearer_auth(&auth_token)
        .json(&json!({
            "name": hc_name,
            "description": description,
            "region": region,
            "type": "TCP",
            "tcpHealthCheck": {
                "port": hc_port,
                "portSpecification": "GCE_VM_IP_PORT"
            }
        }))
        .send()
        .await?
        .json::<Value>()
        .await?;
    if utils::wait_for_op(&project, &auth_token, Some(region), None, &res).await? {
        debug!("health check update operation completed: {}", hc_name);
        let svc = utils::get_svc(svc_name, svc_ns, k8s_client).await?;
        utils::annotate_svc(&svc, LB_HC_ANNOTATION_KEY, hc_name, k8s_client).await?;
        Ok(())
    } else {
        Err(anyhow!(
            "error occurred updating tcp health check for svc namespace/service: {}/{} error: {:?}",
            svc_ns,
            svc_name,
            res["statusMessage"].as_str()
        ))
    }
}

async fn create_firewall_rule(
    svc_name: &String,
    svc_ns: &String,
    ports: Vec<i32>,
    description: &String,
    k8s_client: &Client,
) -> anyhow::Result<()> {
    let auth_token = gcp_auth::get_access_token().await?;
    let args = Args::parse();
    let network = args.network;
    let shared_vpc_project_id = args.shared_vpc_project_id;
    let project = if !shared_vpc_project_id.is_empty() {
        shared_vpc_project_id
    } else {
        gcp_auth::get_project_id().await?
    };
    let res = reqwest::Client::new()
        .post(urls::compute_url(&[
            "compute",
            "v1",
            "projects",
            &project,
            "global",
            "firewalls",
        ])?)
        .header(ACCEPT, "application/json")
        .bearer_auth(&auth_token)
        .json(&utils::build_firewalls_payload(
            format!("fw-{}-{}-{}", svc_ns, svc_name, utils::random_string()),
            description,
            utils::build_network_url(&project, &network)?,
            ports,
        )?)
        .send()
        .await?
        .json::<Value>()
        .await?;
    if utils::wait_for_op(&project, &auth_token, None, None, &res).await? {
        debug!("created firewall rule for service: {}/{}", svc_ns, svc_name);
        let svc = utils::get_svc(svc_name, svc_ns, k8s_client).await?;
        let target_link = res["targetLink"].as_str().unwrap();
        let firewall_rule = &target_link.split("/").last().unwrap().to_string();
        utils::annotate_svc(
            &svc,
            LB_FIREWALL_RULE_ANNOTATION_KEY,
            firewall_rule,
            k8s_client,
        )
        .await?;
        Ok(())
    } else {
        Err(anyhow!(
            "error occurred creating firewall rule for svc namespace/service: {}/{} error: {:?}",
            svc_ns,
            svc_name,
            res["statusMessage"].as_str()
        ))
    }
}

async fn update_firewall_rule(
    firewall_rule: &String,
    description: &String,
    svc_name: &String,
    svc_ns: &String,
    ports: Vec<i32>,
    k8s_client: &Client,
) -> anyhow::Result<()> {
    let auth_token = gcp_auth::get_access_token().await?;
    let args = Args::parse();
    let network = args.network;
    let shared_vpc_project_id = args.shared_vpc_project_id;
    let project = if !shared_vpc_project_id.is_empty() {
        shared_vpc_project_id
    } else {
        gcp_auth::get_project_id().await?
    };
    let url = urls::compute_url(&[
        "compute",
        "v1",
        "projects",
        &project,
        "global",
        "firewalls",
        firewall_rule,
    ])?;
    ownership::require_owned_resource(
        &url,
        &auth_token,
        Owner::Service {
            namespace: svc_ns,
            name: svc_name,
        },
        LB_FIREWALL_RULE_ANNOTATION_KEY,
    )
    .await?;
    let res = reqwest::Client::new()
        .put(&url)
        .header(ACCEPT, "application/json")
        .bearer_auth(&auth_token)
        .json(&utils::build_firewalls_payload(
            String::from(firewall_rule),
            description,
            utils::build_network_url(&project, &network)?,
            ports,
        )?)
        .send()
        .await?
        .json::<Value>()
        .await?;
    if utils::wait_for_op(&project, &auth_token, None, None, &res).await? {
        debug!("firewall rule updated: {}", firewall_rule);
        let svc = utils::get_svc(svc_name, svc_ns, k8s_client).await?;
        utils::annotate_svc(
            &svc,
            LB_FIREWALL_RULE_ANNOTATION_KEY,
            firewall_rule,
            k8s_client,
        )
        .await?;
        Ok(())
    } else {
        Err(anyhow!(
            "error occurred updating firewall rule for svc namespace/service: {}/{} error: {:?}",
            svc_ns,
            svc_name,
            res["statusMessage"].as_str()
        ))
    }
}

pub(crate) async fn process_instance_groups(
    svc: &Arc<Service>,
    region: &String,
    svc_annotations: &BTreeMap<String, String>,
    k8s_client: &Client,
) -> anyhow::Result<()> {
    let project = gcp_auth::get_project_id().await?;
    let auth_token = gcp_auth::get_access_token().await?;
    let mut svc_instance_groups = HashMap::new();

    if svc_annotations
        .keys()
        .find(|&k| k.eq(LB_REGIONAL_MIG_ANNOTATION_KEY) || k.eq(LB_ZONAL_MIG_ANNOTATION_KEY))
        .is_none()
    {
        let instances_map = utils::get_zones_to_instances_map(k8s_client).await?;
        let description = ownership::ownership_marker(&svc.namespace().unwrap(), &svc.name_any());
        for (zone, instances) in instances_map {
            let ig_name = validation::controller_instance_group_name(&zone);
            let ig_url = urls::compute_url(&[
                "compute",
                "beta",
                "projects",
                &project,
                "zones",
                &zone,
                "instanceGroups",
                &ig_name,
            ])?;
            if ownership::get_owned_resource(
                &ig_url,
                &auth_token,
                Owner::AnyService,
                LB_IG_ANNOTATION_KEY,
            )
            .await?
            .is_none()
            {
                create_instance_group(&project, &auth_token, &ig_name, &zone, &description).await?;
                ownership::require_owned_resource(
                    &ig_url,
                    &auth_token,
                    Owner::AnyService,
                    LB_IG_ANNOTATION_KEY,
                )
                .await?;
            }
            if !check_if_all_instances_exist_in_instance_group(
                &project, &zone, &ig_name, &instances,
            )
            .await?
            {
                add_instances_to_instance_group(
                    &project,
                    region,
                    &auth_token,
                    &zone,
                    &ig_name,
                    instances,
                )
                .await?;
            }
            svc_instance_groups.insert(zone.clone(), ig_name.clone());
        }
    }

    if !svc_instance_groups.is_empty() {
        utils::annotate_svc(
            &svc,
            LB_IG_ANNOTATION_KEY,
            &serde_json::to_string(&svc_instance_groups)?,
            k8s_client,
        )
        .await?;
    }
    Ok(())
}

async fn create_instance_group(
    project: &String,
    auth_token: &String,
    ig_name: &String,
    zone: &String,
    description: &String,
) -> anyhow::Result<()> {
    let res = reqwest::Client::new()
        .post(urls::compute_url(&[
            "compute",
            "v1",
            "projects",
            project,
            "zones",
            zone,
            "instanceGroups",
        ])?)
        .header(ACCEPT, "application/json")
        .bearer_auth(&auth_token)
        .json(&json!({
            "name": ig_name,
            "description": description
        }))
        .send()
        .await?
        .json::<Value>()
        .await?;
    debug!("create instance group response: {:?}", res);
    if utils::wait_for_op(&project, &auth_token, None, Some(&zone), &res).await?
        || res["error"]["errors"].as_array().iter().any(|&e| {
            e.iter()
                .any(|e| e["reason"].as_str().eq(&Some("alreadyExists")))
        })
    {
        debug!("instance group created: {}", ig_name);
        Ok(())
    } else {
        Err(anyhow!(
            "instance group creation failed, response: {}",
            serde_json::to_string(&res)?
        ))
    }
}

pub(crate) async fn add_instances_to_instance_group(
    project: &String,
    region: &String,
    auth_token: &String,
    zone: &String,
    instance_group: &String,
    instances: Vec<String>,
) -> anyhow::Result<()> {
    for instance_name in &instances {
        let payload = json!({
            "instances": [
            {
                "instance": utils::build_instance_url(project, zone, instance_name)?
            }
        ]});
        debug!(
            "add instance to the group: {}/{} payload: {}",
            instance_name,
            instance_group,
            serde_json::to_string(&payload)?
        );
        let res = reqwest::Client::new()
            .post(urls::compute_url(&[
                "compute",
                "v1",
                "projects",
                project,
                "zones",
                zone,
                "instanceGroups",
                instance_group,
                "addInstances",
            ])?)
            .header(ACCEPT, "application/json")
            .bearer_auth(auth_token)
            .json(&payload)
            .send()
            .await?
            .json::<Value>()
            .await?;
        if utils::wait_for_op(&project, &auth_token, Some(region), Some(&zone), &res).await?
            || res["error"]["errors"].as_array().iter().any(|&e| {
                e.iter()
                    .any(|e| e["reason"].as_str().eq(&Some("memberAlreadyExists")))
            })
        {
            debug!(
                "added instance to the group: {}/{}",
                instance_name, instance_group
            );
        } else {
            return Err(anyhow!(
                "failed to add instance to the group: {}/{} response: {}",
                instance_name,
                instance_group,
                serde_json::to_string(&res)?
            ));
        }
    }
    Ok(())
}

pub(crate) async fn process_backend_service(
    svc: &Arc<Service>,
    region: &String,
    annotations: &BTreeMap<String, String>,
    k8s_client: &Client,
) -> anyhow::Result<()> {
    let project = gcp_auth::get_project_id().await?;
    let auth_token = gcp_auth::get_access_token().await?;
    let service_name = &svc.name_any();
    let service_ns = &svc.namespace().unwrap();
    let hc_name = validation::resource_name_annotation(annotations, LB_HC_ANNOTATION_KEY)?
        .ok_or_else(|| {
            anyhow!(
                "{} annotation does not exist for service: {}/{}",
                LB_HC_ANNOTATION_KEY,
                service_ns,
                service_name
            )
        })?;
    let backend_svc =
        validation::resource_name_annotation(annotations, LB_BACKEND_SVC_ANNOTATION_KEY)?;
    let description = ownership::ownership_marker(service_ns, service_name);

    let hc_api_url = urls::compute_url(&[
        "compute",
        "v1",
        "projects",
        &project,
        "regions",
        region,
        "healthChecks",
        hc_name,
    ])?;
    ownership::require_owned_resource(
        &hc_api_url,
        &auth_token,
        Owner::Service {
            namespace: service_ns,
            name: service_name,
        },
        LB_HC_ANNOTATION_KEY,
    )
    .await?;

    if let Some(ig_annotation) = annotations.get(LB_IG_ANNOTATION_KEY) {
        let controller_groups =
            validation::parse_controller_instance_groups(ig_annotation, region)?;
        for (zone, group) in &controller_groups {
            let ig_url = urls::compute_url(&[
                "compute",
                "beta",
                "projects",
                &project,
                "zones",
                zone,
                "instanceGroups",
                group,
            ])?;
            ownership::require_owned_resource(
                &ig_url,
                &auth_token,
                Owner::AnyService,
                LB_IG_ANNOTATION_KEY,
            )
            .await?;
        }
    }

    let backends = build_backends(region, annotations, &project, service_name, service_ns)?;
    let hc_url = utils::build_health_check_url(&project, region, hc_name)?;
    if let Some(backend_svc) = backend_svc {
        debug!(
            "backend service annotation exists, updating: {}",
            backend_svc
        );
        let update_payload = json!({
            "name": backend_svc,
            "description": description,
            "protocol": "TCP",
            "backends": backends,
            "healthChecks": [hc_url],
            "loadBalancingScheme": "EXTERNAL"
        });
        debug!(
            "update backend service payload: {}",
            serde_json::to_string(&update_payload)?
        );
        let backend_svc_url = urls::compute_url(&[
            "compute",
            "beta",
            "projects",
            &project,
            "regions",
            region,
            "backendServices",
            backend_svc,
        ])?;
        ownership::require_owned_resource(
            &backend_svc_url,
            &auth_token,
            Owner::Service {
                namespace: service_ns,
                name: service_name,
            },
            LB_BACKEND_SVC_ANNOTATION_KEY,
        )
        .await?;
        let res = reqwest::Client::new()
            .patch(&backend_svc_url)
            .header(ACCEPT, "application/json")
            .bearer_auth(&auth_token)
            .json(&update_payload)
            .send()
            .await?
            .json::<Value>()
            .await?;
        debug!("update backend service response: {:?}", res);
        if utils::wait_for_op(&project, &auth_token, Some(region), None, &res).await? {
            debug!(
                "updated backend service: {} for service {}/{}",
                backend_svc, service_ns, service_name
            );
        } else {
            return Err(anyhow!(
                "failed to update backend for service: {}/{}, error_message: {}",
                service_ns,
                service_name,
                res["statusMessage"]
            ));
        }
    } else {
        let create_payload = json!({
            "name": format!("backend-svc-{}-{}-{}", service_ns, service_name, utils::random_string()),
            "description": description,
            "protocol": "TCP",
            "backends": backends,
            "healthChecks": [hc_url],
            "loadBalancingScheme": "EXTERNAL"
        });
        debug!(
            "create backend service payload: {}",
            serde_json::to_string(&create_payload)?
        );
        let res = reqwest::Client::new()
            .post(urls::compute_url(&[
                "compute",
                "beta",
                "projects",
                &project,
                "regions",
                region,
                "backendServices",
            ])?)
            .header(ACCEPT, "application/json")
            .bearer_auth(&auth_token)
            .json(&create_payload)
            .send()
            .await?
            .json::<Value>()
            .await?;
        debug!("create backend service response: {:?}", res);
        if utils::wait_for_op(&project, &auth_token, Some(region), None, &res).await? {
            let target_link = res["targetLink"].as_str().unwrap();
            let backend_svc = &target_link.split("/").last().unwrap().to_string();
            debug!(
                "created backend service {} for service {}/{}",
                backend_svc, service_ns, service_name
            );
            utils::annotate_svc(&svc, LB_BACKEND_SVC_ANNOTATION_KEY, backend_svc, k8s_client)
                .await?;
        } else {
            return Err(anyhow!(
                "failed to create backend for service: {}/{}, error_message: {}",
                service_ns,
                service_name,
                res["statusMessage"]
            ));
        }
    }
    Ok(())
}

fn build_backends(
    region: &str,
    annotations: &BTreeMap<String, String>,
    project: &str,
    service_name: &str,
    service_ns: &str,
) -> anyhow::Result<Vec<HashMap<String, String>>> {
    if let Some(unmanaged_ig) = annotations.get(LB_IG_ANNOTATION_KEY) {
        debug!(
            "using zonal unmanaged instance groups for service: {}/{}",
            service_ns, service_name
        );
        return build_zonal_instance_group_backends(
            project,
            service_ns,
            service_name,
            LB_IG_ANNOTATION_KEY,
            unmanaged_ig,
        );
    }
    if let Some(zonal_ig) = annotations.get(LB_ZONAL_MIG_ANNOTATION_KEY) {
        debug!(
            "using zonal managed instance groups for service: {}/{}",
            service_ns, service_name
        );
        return build_zonal_instance_group_backends(
            project,
            service_ns,
            service_name,
            LB_ZONAL_MIG_ANNOTATION_KEY,
            zonal_ig,
        );
    }
    let mut backends = vec![];
    if let Some(managed_ig) = annotations.get(LB_REGIONAL_MIG_ANNOTATION_KEY) {
        for group in managed_ig.split(',') {
            validation::validate_resource_name(LB_REGIONAL_MIG_ANNOTATION_KEY, group)?;
            let group_name = group.to_string();
            let mut backend = HashMap::<String, String>::new();
            backend.insert(
                String::from("group"),
                utils::build_regional_instance_group_url(project, region, &group_name)?,
            );
            backend.insert(String::from("balancingMode"), String::from("CONNECTION"));
            backends.push(backend);
        }
        debug!(
            "using provided regional managed instance groups for service: {}/{} count: {}",
            service_ns,
            service_name,
            backends.len()
        );
    }
    if backends.is_empty() {
        return Err(anyhow!(
            "error occurred building backends for service: {}/{}",
            service_ns,
            service_name
        ));
    }
    Ok(backends)
}

fn build_zonal_instance_group_backends(
    project: &str,
    svc_ns: &str,
    svc_name: &str,
    annotation_key: &str,
    instance_groups: &str,
) -> anyhow::Result<Vec<HashMap<String, String>>> {
    let mut backends = vec![];
    let groups: BTreeMap<String, String> =
        serde_json::from_str(instance_groups).with_context(|| {
            format!(
                "invalid {} {}: expected JSON object mapping zone to instance group",
                annotation_key,
                validation::display_untrusted(instance_groups)
            )
        })?;
    for (zone, group_name) in groups {
        validation::validate_resource_name(annotation_key, &zone)?;
        validation::validate_resource_name(annotation_key, &group_name)?;
        let mut backend = HashMap::<String, String>::new();
        backend.insert(
            String::from("group"),
            utils::build_zonal_instance_group_url(project, &zone, &group_name)?,
        );
        backend.insert(String::from("balancingMode"), String::from("CONNECTION"));
        backends.push(backend);
    }
    debug!(
        "number of zonal instance groups for service: {}/{} count: {}",
        svc_ns,
        svc_name,
        backends.len()
    );
    Ok(backends)
}

pub(crate) async fn process_forwarding_rule(
    svc: &Arc<Service>,
    region: &String,
    annotations: &BTreeMap<String, String>,
    k8s_client: &Client,
) -> anyhow::Result<()> {
    let project = gcp_auth::get_project_id().await?;
    let auth_token = gcp_auth::get_access_token().await?;
    let forwarding_rule =
        validation::resource_name_annotation(annotations, LB_FORWARDING_RULE_ANNOTATION_KEY)?;
    let static_ip_name =
        validation::resource_name_annotation(annotations, LB_STATIC_IP_ANNOTATION_KEY)?;
    if let Some(forwarding_rule) = forwarding_rule {
        let service_ns = svc.namespace().unwrap();
        let service_name = svc.name_any();
        let fr_url = urls::compute_url(&[
            "compute",
            "beta",
            "projects",
            &project,
            "regions",
            region,
            "forwardingRules",
            forwarding_rule,
        ])?;
        let fr_resource = ownership::require_owned_resource(
            &fr_url,
            &auth_token,
            Owner::Service {
                namespace: &service_ns,
                name: &service_name,
            },
            LB_FORWARDING_RULE_ANNOTATION_KEY,
        )
        .await?;
        if let Some(name) = static_ip_name {
            let forwarding_rule_ip = forwarding_rule_ip_address(&fr_resource, forwarding_rule)?;
            let static_ip = get_ip_addr(name, &project, &auth_token, Some(region)).await?;
            if forwarding_rule_ip.ne(&static_ip) {
                debug!(
                    "static ip changed, recreating forwarding-rule for service: {}/{}",
                    service_ns, service_name
                );
                delete_forwarding_rule(&svc, &project, &auth_token, region).await?;
                create_forwarding_rule(&svc, &project, &auth_token, region, annotations, k8s_client)
                    .await?
            }
        }
    } else {
        create_forwarding_rule(&svc, &project, &auth_token, region, annotations, k8s_client)
            .await?;
    }
    Ok(())
}

pub(crate) async fn create_forwarding_rule(
    svc: &Arc<Service>,
    project: &String,
    auth_token: &String,
    region: &String,
    annotations: &BTreeMap<String, String>,
    k8s_client: &Client,
) -> anyhow::Result<()> {
    let service_name = &svc.name_any();
    let service_ns = &svc.namespace().unwrap();
    let backend_svc =
        validation::resource_name_annotation(annotations, LB_BACKEND_SVC_ANNOTATION_KEY)?
            .ok_or_else(|| {
                anyhow!(
                    "{} annotation does not exist for service: {}/{}",
                    LB_BACKEND_SVC_ANNOTATION_KEY,
                    service_ns,
                    service_name
                )
            })?;
    let static_ip_name =
        validation::resource_name_annotation(annotations, LB_STATIC_IP_ANNOTATION_KEY)?;
    let backend_svc_api_url = urls::compute_url(&[
        "compute",
        "beta",
        "projects",
        project,
        "regions",
        region,
        "backendServices",
        backend_svc,
    ])?;
    ownership::require_owned_resource(
        &backend_svc_api_url,
        auth_token,
        Owner::Service {
            namespace: service_ns,
            name: service_name,
        },
        LB_BACKEND_SVC_ANNOTATION_KEY,
    )
    .await?;
    let description = ownership::ownership_marker(service_ns, service_name);
    let ports = svc
        .spec
        .borrow()
        .into_iter()
        .flat_map(|t| t.ports.borrow())
        .flatten()
        .map(|t| t.port)
        .collect::<Vec<_>>();
    let backend_svc_url = utils::build_backend_svc_url(project, region, backend_svc)?;
    let payload = match static_ip_name {
        Some(name) => json!({
            "name": format!("forwarding-rule-{}-{}-{}", service_ns, service_name, utils::random_string()),
            "description": description,
            "IPProtocol": "TCP",
            "IPAddress": utils::build_address_url(project, region, name)?,
            "loadBalancingScheme": "EXTERNAL",
            "backendService": backend_svc_url,
            "ports": ports
        }),
        None => json!({
            "name": format!("forwarding-rule-{}-{}-{}", service_ns, service_name, utils::random_string()),
            "description": description,
            "IPProtocol": "TCP",
            "loadBalancingScheme": "EXTERNAL",
            "backendService": backend_svc_url,
            "ports": ports
        }),
    };
    debug!(
        "create forwarding rule payload: {}",
        serde_json::to_string_pretty(&payload)?
    );
    let res = reqwest::Client::new()
        .post(urls::compute_url(&[
            "compute",
            "beta",
            "projects",
            project,
            "regions",
            region,
            "forwardingRules",
        ])?)
        .header(ACCEPT, "application/json")
        .bearer_auth(&auth_token)
        .json(&payload)
        .send()
        .await?
        .json::<Value>()
        .await?;
    debug!(
        "create forwarding rule for service: {}/{} response: {:?}",
        service_ns, service_name, res
    );
    if utils::wait_for_op(&project, &auth_token, Some(region), None, &res).await? {
        debug!("create forwarding-rule status: {}", res["status"]);
        let target_link = res["targetLink"].as_str().unwrap();
        let forwarding_rule = &target_link.split("/").last().unwrap().to_string();
        utils::annotate_svc(
            &svc,
            LB_FORWARDING_RULE_ANNOTATION_KEY,
            forwarding_rule,
            k8s_client,
        )
        .await?;
        let fr_url = urls::compute_url(&[
            "compute",
            "beta",
            "projects",
            project,
            "regions",
            region,
            "forwardingRules",
            forwarding_rule,
        ])?;
        let fr_resource = ownership::require_owned_resource(
            &fr_url,
            auth_token,
            Owner::Service {
                namespace: service_ns,
                name: service_name,
            },
            LB_FORWARDING_RULE_ANNOTATION_KEY,
        )
        .await?;
        let ip_address = forwarding_rule_ip_address(&fr_resource, forwarding_rule)?;
        utils::update_svc_lb_status(&svc, ip_address, k8s_client)
            .await
            .map_err(ControllerError)?;
        Ok(())
    } else {
        Err(anyhow!(
            "failed to create forwarding rule, error_message: {}",
            res["statusMessage"]
        ))
    }
}

pub(crate) async fn check_if_all_instances_exist_in_instance_group(
    project: &str,
    zone: &str,
    group: &str,
    instances: &Vec<String>,
) -> anyhow::Result<bool> {
    let auth_token = gcp_auth::get_access_token().await?;
    let res = reqwest::Client::new()
        .post(urls::compute_url(&[
            "compute",
            "beta",
            "projects",
            project,
            "zones",
            zone,
            "instanceGroups",
            group,
            "listInstances",
        ])?)
        .header(ACCEPT, "application/json")
        .bearer_auth(&auth_token)
        .json(&json!({
            "instanceState": "ALL"
        }))
        .send()
        .await?
        .json::<Value>()
        .await?;
    let current_instances = res["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| i.as_str())
        .collect::<Vec<_>>();
    for instance in instances {
        if !current_instances
            .iter()
            .any(|&i| i.split("/").last().eq(&Some(instance)))
        {
            return Ok(false);
        }
    }
    Ok(!current_instances.is_empty() && true)
}

pub(crate) fn forwarding_rule_ip_address(
    resource: &Value,
    forwarding_rule: &str,
) -> anyhow::Result<String> {
    match resource["IPAddress"].as_str() {
        Some(ip) => Ok(ip.to_string()),
        None => Err(anyhow!(
            "failed to get forwarding rule ip address: {}",
            validation::display_untrusted(forwarding_rule)
        )),
    }
}

pub(crate) async fn get_ip_addr(
    name: &String,
    project: &str,
    auth_token: &String,
    region: Option<&String>,
) -> anyhow::Result<String> {
    let endpoint = match region {
        Some(r) => urls::compute_url(&[
            "compute",
            "v1",
            "projects",
            project,
            "regions",
            r,
            "addresses",
            name,
        ])?,
        None => urls::compute_url(&[
            "compute",
            "v1",
            "projects",
            project,
            "global",
            "addresses",
            name,
        ])?,
    };
    let res = reqwest::Client::new()
        .get(endpoint)
        .bearer_auth(auth_token)
        .send()
        .await?
        .json::<Value>()
        .await?;
    match res["address"].as_str() {
        Some(ip) => Ok(ip.to_string()),
        None => Err(anyhow!(
            "error occurred fetching the ip address by name: {}",
            name
        )),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::forwarding_rule_ip_address;

    #[test]
    fn forwarding_rule_ip_address_extracts_present_ip_and_errors_when_missing() {
        let present = json!({
            "name": "fr-1",
            "IPAddress": "203.0.113.10"
        });
        assert_eq!(
            forwarding_rule_ip_address(&present, "fr-1").unwrap(),
            "203.0.113.10"
        );

        let missing = json!({"name": "fr-1"});
        assert!(forwarding_rule_ip_address(&missing, "fr-1").is_err());
    }
}
