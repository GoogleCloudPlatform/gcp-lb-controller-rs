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

use anyhow::{anyhow, bail};
use reqwest::header::ACCEPT;
use reqwest::StatusCode;
use serde_json::Value;

use crate::constants::CONTROLLER_NAME;
use crate::validation::display_untrusted;

/// "gcp-lb-controller/service: " (built from CONTROLLER_NAME)
pub(crate) fn ownership_marker_prefix() -> String {
    format!("{}/service: ", CONTROLLER_NAME)
}

/// "gcp-lb-controller/service: <ns>/<name>": byte-identical to what every released version wrote.
pub(crate) fn ownership_marker(service_ns: &str, service_name: &str) -> String {
    format!(
        "{}{}/{}",
        ownership_marker_prefix(),
        service_ns,
        service_name
    )
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Owner<'a> {
    /// description must equal ownership_marker(namespace, name)
    Service { namespace: &'a str, name: &'a str },
    /// description must start with ownership_marker_prefix() (instance groups are shared by all Services)
    AnyService,
}

/// Pure: does `resource["description"]` satisfy `owner`? Missing or non-string description -> Err.
pub(crate) fn check_owner(resource: &Value, owner: Owner<'_>, what: &str) -> anyhow::Result<()> {
    let (expected, recovery) = match owner {
        Owner::Service { namespace, name } => (
            format!("description {:?}", ownership_marker(namespace, name)),
            "correct or remove the annotation to recover",
        ),
        Owner::AnyService => (
            format!("description starting with {:?}", ownership_marker_prefix()),
            "this instance group was not created by the controller; \
             rename or remove the group, or correct the annotation, to recover",
        ),
    };

    let found = match resource.get("description") {
        None | Some(Value::Null) => {
            bail!(
                "ownership verification failed for {}: expected {}, found missing description; \
                 controller refuses to use, update or delete this resource; {}",
                what,
                expected,
                recovery
            );
        }
        Some(Value::String(desc)) => desc.as_str(),
        Some(other) => {
            let rendered = other.to_string();
            bail!(
                "ownership verification failed for {}: expected {}, found non-string description {}; \
                 controller refuses to use, update or delete this resource; {}",
                what,
                expected,
                display_untrusted(&rendered),
                recovery
            );
        }
    };

    let matches = match owner {
        Owner::Service { namespace, name } => found == ownership_marker(namespace, name),
        Owner::AnyService => found
            .strip_prefix(&ownership_marker_prefix())
            .is_some_and(|rest| !rest.is_empty()),
    };

    if !matches {
        bail!(
            "ownership verification failed for {}: expected {}, found {}; \
             controller refuses to use, update or delete this resource; {}",
            what,
            expected,
            display_untrusted(found),
            recovery
        );
    }

    Ok(())
}

/// Pure: 404 -> Ok(false); 2xx -> Ok(true); anything else -> Err.
pub(crate) fn resource_exists(status: StatusCode, what: &str) -> anyhow::Result<bool> {
    if status == StatusCode::NOT_FOUND {
        Ok(false)
    } else if status.is_success() {
        Ok(true)
    } else {
        bail!(
            "unexpected HTTP status {} while checking {}: refusing to treat resource as absent",
            status,
            what
        )
    }
}

fn resource_label(what: &str, url: &str) -> String {
    format!("{} ({})", what, url)
}

/// GET url. Ok(None) if absent; Ok(Some(resource)) if it exists and check_owner passes; Err otherwise.
pub(crate) async fn get_owned_resource(
    url: &str,
    auth_token: &str,
    owner: Owner<'_>,
    what: &str,
) -> anyhow::Result<Option<Value>> {
    let label = resource_label(what, url);
    let response = reqwest::Client::new()
        .get(url)
        .header(ACCEPT, "application/json")
        .bearer_auth(auth_token)
        .send()
        .await?;
    if !resource_exists(response.status(), &label)? {
        return Ok(None);
    }
    let resource = response.json::<Value>().await?;
    check_owner(&resource, owner, &label)?;
    Ok(Some(resource))
}

/// As get_owned_resource, but an absent resource is an error.
pub(crate) async fn require_owned_resource(
    url: &str,
    auth_token: &str,
    owner: Owner<'_>,
    what: &str,
) -> anyhow::Result<Value> {
    get_owned_resource(url, auth_token, owner, what)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "owned resource for {} does not exist (HTTP 404); \
                 controller refuses to proceed; correct or remove the annotation",
                resource_label(what, url)
            )
        })
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;
    use serde_json::json;

    use super::{check_owner, ownership_marker, resource_exists, Owner};

    #[test]
    fn ownership_marker_matches_legacy_format() {
        assert_eq!(
            ownership_marker("default", "web"),
            "gcp-lb-controller/service: default/web"
        );
    }

    #[test]
    fn check_owner_service_accepts_exact_and_rejects_mismatches() {
        let owner = Owner::Service {
            namespace: "default",
            name: "web",
        };
        let label = "gcp-lb-controller/health-check (https://compute.googleapis.com/compute/v1/projects/p/regions/r/healthChecks/hc-1)";
        let owned = json!({
            "name": "hc-1",
            "description": "gcp-lb-controller/service: default/web"
        });
        assert!(check_owner(&owned, owner, label).is_ok());

        for bad in [
            json!({"description": "gcp-lb-controller/service: default/other"}),
            json!({"description": "gcp-lb-controller/service: other/web"}),
            json!({"description": "gcp-lb-controller/service: default/we"}),
            json!({"description": "gcp-lb-controller/service: default/web2"}),
            json!({}),
            json!({"description": null}),
            json!({"description": 12345}),
            json!({"description": ["gcp-lb-controller/service: default/web"]}),
            json!({"description": "Managed by Terraform"}),
        ] {
            let err = check_owner(&bad, owner, label).unwrap_err().to_string();
            assert!(err.contains(label));
            assert!(err.contains("refuses to use, update or delete"));
            assert!(err.contains("correct or remove the annotation"));
        }
    }

    #[test]
    fn check_owner_any_service_accepts_controller_markers_and_rejects_others() {
        let label = "gcp-lb-controller/instance-groups (https://compute.googleapis.com/compute/beta/projects/p/zones/z/instanceGroups/lb-ig-z)";
        for valid in [
            json!({"description": "gcp-lb-controller/service: default/web"}),
            json!({"description": "gcp-lb-controller/service: prod/api-svc"}),
        ] {
            assert!(check_owner(&valid, Owner::AnyService, label).is_ok());
        }

        for invalid in [
            json!({}),
            json!({"description": "Managed by user"}),
            json!({"description": "gcp-lb-controller/service:"}),
            json!({"description": "gcp-lb-controller/service: "}),
            json!({"description": "gcp-lb-controller-extra/service: default/web"}),
            json!({"description": "prefix gcp-lb-controller/service: default/web"}),
        ] {
            let err = check_owner(&invalid, Owner::AnyService, label)
                .unwrap_err()
                .to_string();
            assert!(err.contains(label));
            assert!(err.contains("refuses to use, update or delete"));
            assert!(err.contains("rename or remove the group"));
        }
    }

    #[test]
    fn resource_exists_handles_status_codes_strictly() {
        let label = "gcp-lb-controller/health-check (https://compute.googleapis.com/compute/v1/projects/p/regions/r/healthChecks/hc-1)";
        assert!(!resource_exists(StatusCode::NOT_FOUND, label).unwrap());
        assert!(resource_exists(StatusCode::OK, label).unwrap());

        for status in [
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let err = resource_exists(status, label).unwrap_err().to_string();
            assert!(
                err.contains(label),
                "expected error for status {} to include label: {}",
                status,
                err
            );
        }
    }
}
