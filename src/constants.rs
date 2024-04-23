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

pub const COMPUTE_ENDPOINT: &'static str = "https://compute.googleapis.com";
pub(crate) const DEFAULT_TOKEN_URI: &'static str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
pub(crate) const PROJECT_ID_URI: &'static str =
    "http://metadata.google.internal/computeMetadata/v1/project/project-id";
pub(crate) const INSTANCE_ZONE_URI: &'static str =
    "http://metadata.google.internal/computeMetadata/v1/instance/zone";
pub(crate) const GCP_TOKEN_URI: &str = "https://accounts.google.com/o/oauth2/token";
pub(crate) const CREDENTIALS_FILE: &str = ".config/gcloud/application_default_credentials.json";
pub(crate) const CLEANUP_NUM_RETRIES: i32 = 4;

// Controller annotations
pub(crate) const CONTROLLER_NAME: &str = "gcp-lb-controller";
pub(crate) const LB_STATIC_IP_ANNOTATION_KEY: &str = "gcp-lb-controller/static-ip-name";
pub(crate) const LB_REGIONAL_MIG_ANNOTATION_KEY: &str = "gcp-lb-controller/regional-migs";
pub(crate) const LB_ZONAL_MIG_ANNOTATION_KEY: &str = "gcp-lb-controller/zonal-migs";
pub(crate) const LB_HC_PORT_ANNOTATION_KEY: &str = "gcp-lb-controller/hc-port";
pub(crate) const LB_HC_ANNOTATION_KEY: &str = "gcp-lb-controller/health-check";
pub(crate) const LB_FIREWALL_RULE_ANNOTATION_KEY: &str = "gcp-lb-controller/firewall-rule";
pub(crate) const LB_IG_ANNOTATION_KEY: &str = "gcp-lb-controller/instance-groups";
pub(crate) const LB_BACKEND_SVC_ANNOTATION_KEY: &str = "gcp-lb-controller/backend-svc";
pub(crate) const LB_FORWARDING_RULE_ANNOTATION_KEY: &str = "gcp-lb-controller/forwarding-rule";

// Loadbalancer firewall CIDRs
pub(crate) const NLB_FIREWALL_CIDR: &str = "35.191.0.0/16,209.85.152.0/22,209.85.204.0/22";
