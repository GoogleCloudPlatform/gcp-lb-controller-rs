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

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use anyhow::{anyhow, Context};
use json_patch::{PatchOperation, RemoveOperation, TestOperation};
use k8s_openapi::api::core::v1::{
    LoadBalancerIngress, LoadBalancerStatus, Node, Service, ServiceStatus,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{ListParams, PartialObjectMetaExt, Patch, PatchParams};
use kube::{Api, Client, Resource, ResourceExt};
use log::{debug, info};
use rand::random;
use regex::Regex;
use reqwest::header::ACCEPT;
use serde_json::{json, Value};
use std::borrow::BorrowMut;
use std::sync::Arc;

use crate::constants::{
    COMPUTE_ENDPOINT, CONTROLLER_NAME, LB_REGIONAL_MIG_ANNOTATION_KEY, LB_ZONAL_MIG_ANNOTATION_KEY,
};
use crate::constants::{
    LB_BACKEND_SVC_ANNOTATION_KEY, LB_FIREWALL_RULE_ANNOTATION_KEY,
    LB_FORWARDING_RULE_ANNOTATION_KEY, LB_HC_ANNOTATION_KEY, LB_IG_ANNOTATION_KEY,
    NLB_FIREWALL_CIDR,
};

pub(crate) fn get_hc_name_from_target_link(link: &str) -> anyhow::Result<String> {
    debug!("getting health check name from target link: {}", link);
    let re = Regex::new(r"^(\S+/projects/\S+/regions/\S+/healthChecks/(?P<name>\S+))$").unwrap();
    let caps = re.captures(link);
    match caps {
        Some(caps) => Ok(String::from(&caps["name"])),
        None => Err(anyhow!(
            "error occurred parsing health check name from target link: {}",
            link
        )),
    }
}

pub(crate) fn random_string() -> String {
    format!("{:x}", random::<u64>())
}

pub(crate) async fn get_zones_to_instances_map(
    k8s_client: &Client,
) -> anyhow::Result<HashMap<String, Vec<String>>> {
    let api: Api<Node> = Api::<Node>::all(k8s_client.to_owned());
    let lp = ListParams::default();
    let nodes = api.list(&lp).await?;
    let mut nodes_hostnames = vec![];
    for node in &nodes {
        let metadata = &node.metadata;
        if let Some(labels) = &metadata.labels {
            if let Some(hostname) = labels.get("kubernetes.io/hostname") {
                nodes_hostnames.push(hostname)
            }
        }
    }
    let mut instances_map = HashMap::<String, Vec<String>>::new();
    let re = Regex::new(r"^((?P<instance_name>\S+)\.(?P<zone>\S+)\.c\.\S+\.internal)$").unwrap();
    for host in nodes_hostnames {
        let caps = re.captures(host.as_str());
        if let Some(c) = caps {
            let instance_name = String::from(&c["instance_name"]);
            let zone = String::from(&c["zone"]);
            if instances_map.contains_key(&zone) {
                let mut data = instances_map.get(&zone).unwrap().to_owned();
                data.push(instance_name);
                instances_map.insert(zone.clone(), data);
            } else {
                let data = vec![instance_name];
                instances_map.insert(zone.clone(), data);
            }
        }
    }
    Ok(instances_map)
}

pub(crate) fn get_node_port(port: i32, svc: &Service) -> anyhow::Result<i32> {
    if let Some(spec) = &svc.spec {
        if let Some(ports) = &spec.ports {
            if let Some(svc_port) = ports.iter().filter(|sp| sp.port == port).last() {
                if let Some(np) = svc_port.node_port {
                    return Ok(np);
                }
            }
        }
    }
    Err(anyhow!(
        "node port not found for service: {:?}/{} port: {}",
        svc.namespace(),
        svc.name_any(),
        port
    ))
}

pub(crate) async fn wait_for_op(
    project: &String,
    auth_token: &String,
    region: Option<&String>,
    zone: Option<&String>,
    res: &Value,
) -> anyhow::Result<bool> {
    let mut retries = 4;
    if let Some(operation_id) = res["id"].as_str() {
        while retries != 0 {
            let mut endpoint = format!(
                "{}/compute/v1/projects/{}/global/operations/{}/wait",
                COMPUTE_ENDPOINT, &project, operation_id
            );
            let mut payload = json!({
                "project": project,
                "operation": operation_id
            });
            if let Some(r) = region {
                endpoint = format!(
                    "{}/compute/v1/projects/{}/regions/{}/operations/{}/wait",
                    COMPUTE_ENDPOINT, &project, r, operation_id
                );
                payload = json!({
                    "project": project,
                    "region": region,
                    "operation": operation_id
                });
            }
            if let Some(z) = zone {
                endpoint = format!(
                    "{}/compute/v1/projects/{}/zones/{}/operations/{}/wait",
                    COMPUTE_ENDPOINT, &project, z, operation_id
                );
                payload = json!({
                    "project": project,
                    "zone": zone,
                    "operation": operation_id
                });
            }
            let res = reqwest::Client::new()
                .post(endpoint)
                .header(ACCEPT, "application/json")
                .bearer_auth(auth_token)
                .json(&payload)
                .send()
                .await?
                .json::<Value>()
                .await?;
            let status = res["status"].as_str();
            if status.eq(&Some("DONE")) {
                return Ok(true);
            };
            info!(
                "retrying wait for operation: {} current status: {:?}",
                operation_id, status
            );
            tokio::time::sleep(Duration::from_secs(15)).await;
            retries = retries - 1;
        }
    };
    Ok(false)
}

pub(crate) async fn get_svc(
    svc_name: &String,
    svc_ns: &String,
    k8s_client: &Client,
) -> anyhow::Result<Service> {
    let api: Api<Service> = Api::<Service>::namespaced(k8s_client.to_owned(), svc_ns);
    Ok(api.get(svc_name).await?)
}

pub(crate) async fn annotate_svc(
    svc: &Service,
    key: &str,
    val: &String,
    k8s_client: &Client,
) -> anyhow::Result<()> {
    let service_name = &svc.name_any();
    let service_ns = &svc.namespace().unwrap();
    let api: Api<Service> = Api::<Service>::namespaced(k8s_client.to_owned(), service_ns);

    if svc.annotations().contains_key(key) && svc.annotations().get(key).eq(&Some(val)) {
        debug!(
            "no annotation update needed for service: {}/{} key: {}",
            service_ns, service_name, key
        );
        return Ok(());
    }

    let mut updated = BTreeMap::new();
    if let Some(mut data) = svc.metadata.annotations.to_owned() {
        updated.append(data.borrow_mut());
    }
    let key = String::from(key);
    updated.insert(key.clone(), val.clone());
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
            "failed to annotate service: {}/{} key: {}",
            service_ns, service_name, &key
        )
    })?;
    debug!(
        "annotated service: {}/{} key: {}",
        service_ns, service_name, key
    );
    Ok(())
}

pub(crate) async fn update_svc_lb_status(
    svc: &Arc<Service>,
    ip_address: String,
    k8s_client: &Client,
) -> anyhow::Result<()> {
    let service_name = &svc.name_any();
    let service_ns = &svc.namespace().unwrap();
    let api: Api<Service> = Api::<Service>::namespaced(k8s_client.to_owned(), service_ns);
    let pp = PatchParams::default();
    let status = ServiceStatus {
        load_balancer: Some(LoadBalancerStatus {
            ingress: Some(vec![LoadBalancerIngress {
                ip: Some(ip_address),
                ..Default::default()
            }]),
        }),
        ..Default::default()
    };
    let data = json!({"status": status});
    let svc_updated = api
        .patch_status(service_name, &pp, &Patch::Merge(data))
        .await
        .with_context(|| {
            format!(
                "failed to update lb status for service: {}/{}",
                service_ns, service_name
            )
        })?;
    debug!(
        "updated lb status for service: {}/{} status: {:?}",
        service_ns, service_name, svc_updated.status
    );
    Ok(())
}

pub(crate) fn is_svc_type_lb(svc: &Service) -> bool {
    svc.spec
        .as_ref()
        .map(|spec| spec.type_.eq(&"LoadBalancer".to_string().into()))
        .eq(&Some(true))
}

pub(crate) fn check_if_lb_annotations_exist_on_svc(svc: &Service) -> bool {
    let lb_annotations = vec![
        LB_HC_ANNOTATION_KEY,
        LB_IG_ANNOTATION_KEY,
        LB_FIREWALL_RULE_ANNOTATION_KEY,
        LB_BACKEND_SVC_ANNOTATION_KEY,
        LB_FORWARDING_RULE_ANNOTATION_KEY,
    ];
    for k in lb_annotations {
        return svc.annotations().contains_key(k);
    }
    false
}

pub(crate) fn build_instance_url(project: &String, zone: &String, name: &String) -> String {
    format!("projects/{}/zones/{}/instances/{}", project, zone, name)
}

pub(crate) fn build_zonal_instance_group_url(
    project: &String,
    zone: &String,
    group_name: &String,
) -> String {
    format!(
        "projects/{}/zones/{}/instanceGroups/{}",
        project, zone, group_name
    )
}

pub(crate) fn build_regional_instance_group_url(
    project: &String,
    region: &String,
    group_name: &String,
) -> String {
    format!(
        "projects/{}/regions/{}/instanceGroups/{}",
        project, region, group_name
    )
}

pub(crate) fn build_health_check_url(project: &String, region: &String, name: &String) -> String {
    format!(
        "projects/{}/regions/{}/healthChecks/{}",
        project, region, name
    )
}

pub(crate) fn build_backend_svc_url(project: &String, region: &String, name: &String) -> String {
    format!(
        "projects/{}/regions/{}/backendServices/{}",
        project, region, name
    )
}

pub(crate) fn build_firewalls_payload(
    firewall_rule: String,
    description: &String,
    network_self_link: String,
    ports: Vec<i32>,
) -> anyhow::Result<Value> {
    let mut allowed = vec![];
    for port in &ports {
        let mut data = HashMap::<String, Value>::new();
        data.insert(String::from("IPProtocol"), String::from("TCP").into());
        let mut tcp_ports = vec![];
        tcp_ports.push(port.to_string());
        data.insert(String::from("ports"), tcp_ports.into());
        allowed.push(data);
    }
    let payload = json!({
        "name": firewall_rule,
        "description": description,
        "direction": "INGRESS",
        "network": network_self_link,
        "sourceRanges": NLB_FIREWALL_CIDR
                .split(",")
                .map(|c| String::from(c))
                .collect::<Vec<String>>(),
        "allowed": allowed
    });
    debug!(
        "firewall payload: {}",
        serde_json::to_string_pretty(&payload)?
    );
    Ok(payload)
}

pub(crate) fn check_resource_prerequisites(
    svc_name: &String,
    svc_ns: &String,
    svc_annotations: &BTreeMap<String, String>,
    keys: Vec<&str>,
) -> anyhow::Result<()> {
    for key in keys {
        if !svc_annotations.iter().any(|(k, _)| k.eq(key)) {
            return Err(anyhow!(
                "{} annotation does not exist for service: {}/{}",
                key,
                svc_ns,
                svc_name
            ));
        }
    }
    Ok(())
}

pub(crate) fn check_backend_svc_prerequisites(
    svc_name: &String,
    svc_ns: &String,
    svc_annotations: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
    if !svc_annotations
        .iter()
        .any(|(k, _)| k.eq(LB_HC_ANNOTATION_KEY))
    {
        return Err(anyhow!(
            "{} annotation does not exist for service: {}/{}",
            LB_HC_ANNOTATION_KEY,
            svc_ns,
            svc_name
        ));
    }
    if !(svc_annotations
        .iter()
        .any(|(k, _)| k.eq(LB_REGIONAL_MIG_ANNOTATION_KEY))
        || svc_annotations
            .iter()
            .any(|(k, _)| k.eq(LB_ZONAL_MIG_ANNOTATION_KEY))
        || svc_annotations
            .iter()
            .any(|(k, _)| k.eq(LB_IG_ANNOTATION_KEY)))
    {
        return Err(anyhow!(
            "instance groups are required for service: {}/{}",
            svc_ns,
            svc_name
        ));
    }
    Ok(())
}

pub(crate) fn _check_if_finalizer_exists(svc: &Service) -> bool {
    svc.metadata
        .finalizers
        .iter()
        .flatten()
        .into_iter()
        .any(|f| f.eq(&format!("{}/cleanup", CONTROLLER_NAME)))
}

pub(crate) async fn _remove_finalizer(svc: &Service, k8s_client: &Client) -> anyhow::Result<()> {
    let finalizer = format!("{}/cleanup", CONTROLLER_NAME);
    let service_name = &svc.name_any();
    let service_ns = &svc.namespace().unwrap();
    let api: Api<Service> = Api::<Service>::namespaced(k8s_client.to_owned(), service_ns);
    if let Some(i) = svc
        .meta()
        .finalizers
        .iter()
        .flatten()
        .into_iter()
        .position(|f| f.eq(&format!("{}/cleanup", CONTROLLER_NAME)))
    {
        let finalizer_path = format!("/metadata/finalizers/{}", i);
        api.patch::<Service>(
            &service_name,
            &PatchParams::default(),
            &Patch::Json(json_patch::Patch(vec![
                PatchOperation::Test(TestOperation {
                    path: finalizer_path.clone(),
                    value: finalizer.into(),
                }),
                PatchOperation::Remove(RemoveOperation {
                    path: finalizer_path,
                }),
            ])),
        )
        .await
        .with_context(|| {
            format!(
                "failed to remove finalizer for service: {}/{}",
                service_ns, service_name
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::constants::{
        LB_BACKEND_SVC_ANNOTATION_KEY, LB_HC_ANNOTATION_KEY, LB_IG_ANNOTATION_KEY,
        LB_REGIONAL_MIG_ANNOTATION_KEY, LB_ZONAL_MIG_ANNOTATION_KEY,
    };
    use crate::utils::{
        build_firewalls_payload, check_backend_svc_prerequisites,
        check_if_lb_annotations_exist_on_svc, check_resource_prerequisites,
        get_hc_name_from_target_link, is_svc_type_lb,
    };
    use k8s_openapi::api::core::v1::{Service, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::ResourceExt;
    use serde_json::json;
    use std::borrow::BorrowMut;
    use std::collections::BTreeMap;

    #[test]
    pub fn test_extract_hc_name_from_target_link() {
        let input = "https://www.googleapis.com/compute/v1/projects/project-1234/regions/us-central1/healthChecks/test-hc";
        let res = get_hc_name_from_target_link(input).unwrap();
        assert_eq!(res, "test-hc")
    }

    #[test]
    pub fn test_build_firewalls_payload() {
        let result = build_firewalls_payload(
            String::from("test-firewall-rule"),
            &String::from("test-svc"),
            String::from("projects/project-1234/global/networks/default"),
            vec![80, 443],
        )
        .unwrap();
        let expected = json!({
        "allowed": [
          {
            "IPProtocol": "TCP",
            "ports": [
              "80"
            ]
          },
          {
            "IPProtocol": "TCP",
            "ports": [
              "443"
            ]
          }
        ],
        "direction": "INGRESS",
        "name": "test-firewall-rule",
        "description": "test-svc",
        "network": "projects/project-1234/global/networks/default",
        "sourceRanges": [
          "35.191.0.0/16",
          "209.85.152.0/22",
          "209.85.204.0/22"
        ]});
        assert_eq!(
            serde_json::to_string(&expected).unwrap(),
            serde_json::to_string(&result).unwrap()
        );
    }

    #[test]
    pub fn check_resource_preconditions_returns_an_error_when_annotation_does_not_exist() {
        let data = BTreeMap::new();
        let input = create_test_svc(&data);
        assert!(check_resource_prerequisites(
            &input.name_any(),
            &input.namespace().unwrap(),
            &data,
            vec![LB_HC_ANNOTATION_KEY]
        )
        .is_err());
    }

    #[test]
    pub fn check_resource_preconditions_returns_ok_when_annotation_exists() {
        let mut data = BTreeMap::new();
        data.insert(LB_HC_ANNOTATION_KEY.into(), "test".into());
        let input = create_test_svc(&data);
        assert!(check_resource_prerequisites(
            &input.name_any(),
            &input.namespace().unwrap(),
            &data,
            vec![LB_HC_ANNOTATION_KEY]
        )
        .is_ok());
    }

    #[test]
    pub fn check_resource_preconditions_returns_ok_when_not_all_annotations_exist() {
        let mut data = BTreeMap::new();
        data.insert(LB_HC_ANNOTATION_KEY.into(), "test".into());
        data.insert(LB_BACKEND_SVC_ANNOTATION_KEY.into(), "test".into());
        let input = create_test_svc(&data);
        assert!(check_resource_prerequisites(
            &input.name_any(),
            &input.namespace().unwrap(),
            &data,
            vec![
                LB_HC_ANNOTATION_KEY,
                LB_BACKEND_SVC_ANNOTATION_KEY,
                LB_IG_ANNOTATION_KEY
            ]
        )
        .is_err());
    }

    #[test]
    pub fn check_if_lb_annotations_exist_on_svc_returns_false_when_service_does_not_have_any_lb_annotations(
    ) {
        let data = BTreeMap::new();
        let input = create_test_svc(&data);
        let result = check_if_lb_annotations_exist_on_svc(&input);
        assert_eq!(result, false)
    }

    #[test]
    pub fn check_if_lb_annotations_exist_on_svc_returns_true_when_service_has_lb_annotation() {
        let mut data = BTreeMap::new();
        data.insert(LB_HC_ANNOTATION_KEY.into(), "test-hc".into());
        let input = create_test_svc(&data);
        let result = check_if_lb_annotations_exist_on_svc(&input);
        assert!(result)
    }

    #[test]
    pub fn is_svc_type_lb_returns_true_if_svc_type_is_loadbalancer() {
        let data = BTreeMap::new();
        let mut input = create_test_svc(&data);
        let lb_spec = ServiceSpec {
            ports: None,
            type_: "LoadBalancer".to_string().into(),
            ..Default::default()
        };
        let _ = input.spec.borrow_mut().insert(lb_spec);
        assert!(is_svc_type_lb(&input))
    }

    #[test]
    pub fn is_svc_type_lb_returns_true_if_svc_type_is_cluster_ip() {
        let data = BTreeMap::new();
        let mut input = create_test_svc(&data);
        let lb_spec = ServiceSpec {
            ports: None,
            type_: "ClusterIP".to_string().into(),
            ..Default::default()
        };
        let _ = input.spec.borrow_mut().insert(lb_spec);
        assert_eq!(is_svc_type_lb(&input), false)
    }

    #[test]
    pub fn check_backend_svc_prerequisites_returns_error_when_hc_annotation_does_not_exist() {
        let data = BTreeMap::new();
        let input = create_test_svc(&data);
        let result =
            check_backend_svc_prerequisites(&input.name_any(), &input.namespace().unwrap(), &data);
        assert!(result.is_err());
    }

    #[test]
    pub fn check_backend_svc_prerequisites_returns_error_when_hc_annotation_exists_but_no_ig_or_mig_annotations_exist(
    ) {
        let mut data = BTreeMap::new();
        data.insert(LB_HC_ANNOTATION_KEY.into(), "test-hc".into());
        let input = create_test_svc(&data);
        let result =
            check_backend_svc_prerequisites(&input.name_any(), &input.namespace().unwrap(), &data);
        assert!(result.is_err());
    }

    #[test]
    pub fn check_backend_svc_prerequisites_returns_ok_when_hc_and_ig_annotations_exist() {
        let mut data = BTreeMap::new();
        data.insert(LB_HC_ANNOTATION_KEY.into(), "test-hc".into());
        data.insert(LB_IG_ANNOTATION_KEY.into(), "test-unmanaged-ig".into());
        let input = create_test_svc(&data);
        let result =
            check_backend_svc_prerequisites(&input.name_any(), &input.namespace().unwrap(), &data);
        assert!(result.is_ok());
    }

    #[test]
    pub fn check_backend_svc_prerequisites_returns_ok_when_hc_and_regional_mig_annotations_exist() {
        let mut data = BTreeMap::new();
        data.insert(LB_HC_ANNOTATION_KEY.into(), "test-hc".into());
        data.insert(
            LB_REGIONAL_MIG_ANNOTATION_KEY.into(),
            "test-regional-managed-ig".into(),
        );
        let input = create_test_svc(&data);
        let result =
            check_backend_svc_prerequisites(&input.name_any(), &input.namespace().unwrap(), &data);
        assert!(result.is_ok());
    }

    #[test]
    pub fn check_backend_svc_prerequisites_returns_ok_when_hc_and_zonal_mig_annotations_exist() {
        let mut data = BTreeMap::new();
        data.insert(LB_HC_ANNOTATION_KEY.into(), "test-hc".into());
        data.insert(
            LB_ZONAL_MIG_ANNOTATION_KEY.into(),
            "test-zonal-managed-ig".into(),
        );
        let input = create_test_svc(&data);
        let result =
            check_backend_svc_prerequisites(&input.name_any(), &input.namespace().unwrap(), &data);
        assert!(result.is_ok());
    }

    fn create_test_svc(data: &BTreeMap<String, String>) -> Service {
        let input = Service {
            metadata: ObjectMeta {
                name: "test".to_string().into(),
                namespace: "default".to_string().into(),
                annotations: Option::from(data.to_owned()),
                ..Default::default()
            },
            spec: Option::from(ServiceSpec {
                ports: None,
                type_: "ClusterIP".to_string().into(),
                ..Default::default()
            }),
            status: None,
        };
        input
    }
}
