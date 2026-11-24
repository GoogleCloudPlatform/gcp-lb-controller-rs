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

use anyhow::bail;

use crate::constants::COMPUTE_ENDPOINT;
use crate::validation::validate_path_segment;

/// Joins segments with '/', after validate_path_segment on each. Empty slice is an error.
pub(crate) fn resource_path(segments: &[&str]) -> anyhow::Result<String> {
    if segments.is_empty() {
        bail!("resource path must contain at least one segment");
    }
    for &segment in segments {
        validate_path_segment(segment)?;
    }
    Ok(segments.join("/"))
}

/// "{COMPUTE_ENDPOINT}/{resource_path(segments)}"
pub(crate) fn compute_url(segments: &[&str]) -> anyhow::Result<String> {
    Ok(format!("{}/{}", COMPUTE_ENDPOINT, resource_path(segments)?))
}

#[cfg(test)]
mod tests {
    use super::{compute_url, resource_path};
    use crate::constants::COMPUTE_ENDPOINT;

    #[test]
    fn compute_url_and_resource_path_match_legacy_format_for_valid_inputs() {
        let project = "example.com:my-project";
        let region = "us-central1";
        let rule = "forwarding-rule-default-web-1234";

        let url = compute_url(&[
            "compute",
            "beta",
            "projects",
            project,
            "regions",
            region,
            "forwardingRules",
            rule,
        ])
        .unwrap();
        assert_eq!(
            url,
            format!(
                "{}/compute/beta/projects/{}/regions/{}/forwardingRules/{}",
                COMPUTE_ENDPOINT, project, region, rule
            )
        );

        let path = resource_path(&[
            "projects",
            project,
            "regions",
            region,
            "backendServices",
            "bs-1",
        ])
        .unwrap();
        assert_eq!(
            path,
            format!(
                "projects/{}/regions/{}/backendServices/bs-1",
                project, region
            )
        );
    }

    #[test]
    fn rejects_empty_and_structure_altering_segments() {
        assert!(resource_path(&[]).is_err());
        assert!(compute_url(&[]).is_err());

        for bad in [
            "",
            ".",
            "..",
            "x/../../../../global/addresses/victim-ip",
            "x?project=other",
            "x#fragment",
            "x%2fy",
            "x\\y",
        ] {
            assert!(
                compute_url(&[
                    "compute",
                    "beta",
                    "projects",
                    "proj-1",
                    "regions",
                    "us-central1",
                    "forwardingRules",
                    bad,
                ])
                .is_err(),
                "expected segment {:?} to be rejected",
                bad
            );
        }
    }

    #[test]
    fn parsed_reqwest_url_preserves_exact_segments_without_query_or_fragment() {
        let segments = [
            "compute",
            "v1",
            "projects",
            "example.com:proj-1",
            "zones",
            "us-central1-a",
            "operations",
            "9876543210",
            "wait",
        ];
        let raw = compute_url(&segments).unwrap();
        let parsed = reqwest::Url::parse(&raw).unwrap();

        let parsed_segments: Vec<&str> = parsed.path_segments().unwrap().collect();
        assert_eq!(parsed_segments, segments);
        assert_eq!(parsed.query(), None);
        assert_eq!(parsed.fragment(), None);
    }

    #[test]
    fn legacy_format_url_is_retargeted_by_url_parse_while_compute_url_rejects_it() {
        let malicious = "x/../../../../global/addresses/victim-ip";
        let legacy = format!(
            "{}/compute/beta/projects/proj-1/regions/us-central1/forwardingRules/{}",
            COMPUTE_ENDPOINT, malicious
        );
        let parsed = reqwest::Url::parse(&legacy).unwrap();
        assert_eq!(
            parsed.path(),
            "/compute/beta/projects/proj-1/global/addresses/victim-ip"
        );

        assert!(compute_url(&[
            "compute",
            "beta",
            "projects",
            "proj-1",
            "regions",
            "us-central1",
            "forwardingRules",
            malicious,
        ])
        .is_err());
    }
}
