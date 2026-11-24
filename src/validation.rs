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

use std::collections::BTreeMap;

use anyhow::bail;

use crate::constants::{MAX_LOGGED_VALUE_LEN, MAX_PATH_SEGMENT_LEN, MAX_RESOURCE_NAME_LEN};

/// Renders an untrusted value for logs and errors: at most MAX_LOGGED_VALUE_LEN chars, Debug-escaped.
pub(crate) fn display_untrusted(value: &str) -> String {
    let full = format!("{:?}", value);
    if full.chars().count() <= MAX_LOGGED_VALUE_LEN {
        return full;
    }

    const TRUNCATION_SUFFIX: &str = "...\"";
    let suffix_chars = TRUNCATION_SUFFIX.chars().count();
    let mut out = String::from("\"");
    let mut char_count = 1;
    for ch in value.chars() {
        let escaped: String = ch.escape_debug().collect();
        let escaped_len = escaped.chars().count();
        if char_count + escaped_len + suffix_chars > MAX_LOGGED_VALUE_LEN {
            break;
        }
        out.push_str(&escaped);
        char_count += escaped_len;
    }
    out.push_str(TRUNCATION_SUFFIX);
    out
}

/// GCE resource name: ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$
pub(crate) fn validate_resource_name(kind: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        bail!(
            "invalid {} {}: GCE resource name must not be empty",
            kind,
            display_untrusted(value)
        );
    }
    if value.len() > MAX_RESOURCE_NAME_LEN {
        bail!(
            "invalid {} {}: GCE resource name exceeds maximum length of {} bytes",
            kind,
            display_untrusted(value),
            MAX_RESOURCE_NAME_LEN
        );
    }

    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        bail!(
            "invalid {} {}: GCE resource name must start with a lowercase ASCII letter [a-z]",
            kind,
            display_untrusted(value)
        );
    }
    let last = bytes[bytes.len() - 1];
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        bail!(
            "invalid {} {}: GCE resource name must end with a lowercase ASCII letter or digit [a-z0-9]",
            kind,
            display_untrusted(value)
        );
    }
    if bytes.len() > 2 {
        for &b in &bytes[1..bytes.len() - 1] {
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                bail!(
                    "invalid {} {}: GCE resource name may only contain lowercase ASCII letters, digits, and '-'",
                    kind,
                    display_untrusted(value)
                );
            }
        }
    }
    Ok(())
}

/// One literal URL path segment: 1..=MAX_PATH_SEGMENT_LEN bytes, first byte ASCII alphanumeric,
/// every byte ASCII alphanumeric or one of '-', '.', ':'.
pub(crate) fn validate_path_segment(value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        bail!(
            "invalid URL path segment {}: segment must not be empty",
            display_untrusted(value)
        );
    }
    if value.len() > MAX_PATH_SEGMENT_LEN {
        bail!(
            "invalid URL path segment {}: segment exceeds maximum length of {} bytes",
            display_untrusted(value),
            MAX_PATH_SEGMENT_LEN
        );
    }

    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        bail!(
            "invalid URL path segment {}: segment must start with an ASCII alphanumeric character",
            display_untrusted(value)
        );
    }
    for &b in bytes {
        if !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':')) {
            bail!(
                "invalid URL path segment {}: segment may only contain ASCII alphanumeric characters, '-', '.', or ':'",
                display_untrusted(value)
            );
        }
    }
    Ok(())
}

/// Value of annotation `key` if present, validated with validate_resource_name. Absent -> Ok(None).
pub(crate) fn resource_name_annotation<'a>(
    annotations: &'a BTreeMap<String, String>,
    key: &str,
) -> anyhow::Result<Option<&'a String>> {
    match annotations.get(key) {
        Some(value) => {
            validate_resource_name(key, value)?;
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        display_untrusted, resource_name_annotation, validate_path_segment, validate_resource_name,
    };
    use crate::constants::{
        LB_FORWARDING_RULE_ANNOTATION_KEY, MAX_LOGGED_VALUE_LEN, MAX_PATH_SEGMENT_LEN,
        MAX_RESOURCE_NAME_LEN,
    };

    #[test]
    fn validate_resource_name_accepts_valid_names() {
        assert!(validate_resource_name("resource", "a").is_ok());
        assert!(validate_resource_name("resource", "a0").is_ok());
        assert!(validate_resource_name("resource", "tcp-hc-default-web-80-1a2b3c4d").is_ok());
        let max_name = format!("a{}0", "b".repeat(MAX_RESOURCE_NAME_LEN - 2));
        assert_eq!(max_name.len(), MAX_RESOURCE_NAME_LEN);
        assert!(validate_resource_name("resource", &max_name).is_ok());
    }

    #[test]
    fn validate_resource_name_rejects_invalid_and_traversal_values() {
        let too_long = "a".repeat(MAX_RESOURCE_NAME_LEN + 1);
        let cases = [
            "x/../../../../global/addresses/victim-ip",
            "x?project=other&requestId=evil",
            "x#drop",
            "..",
            ".",
            "x/y",
            "x%2fy",
            "x%2e%2e",
            "x\\y",
            "x y",
            "x\ny",
            "x\ty",
            "",
            too_long.as_str(),
            "Abc",
            "abC",
            "aBc",
            "1abc",
            "-abc",
            "abc-",
            "a_b",
            "aé",
        ];
        for case in cases {
            assert!(
                validate_resource_name("test-key", case).is_err(),
                "expected resource name {:?} to be rejected",
                case
            );
        }
    }

    #[test]
    fn validate_path_segment_accepts_valid_segments() {
        for valid in [
            "compute",
            "forwardingRules",
            "example.com:my-project",
            "1234567890123456789",
        ] {
            assert!(
                validate_path_segment(valid).is_ok(),
                "expected segment {:?} to be accepted",
                valid
            );
        }
    }

    #[test]
    fn validate_path_segment_rejects_invalid_segments() {
        let over_long = "a".repeat(MAX_PATH_SEGMENT_LEN + 1);
        let cases = [
            "",
            ".",
            "..",
            ".a",
            "-a",
            "a/b",
            "a?b",
            "a#b",
            "a%2fb",
            "a\\b",
            "a b",
            "a\nb",
            over_long.as_str(),
        ];
        for case in cases {
            assert!(
                validate_path_segment(case).is_err(),
                "expected segment {:?} to be rejected",
                case
            );
        }
    }

    #[test]
    fn resource_name_annotation_handles_absent_valid_and_invalid_values() {
        let mut annotations = BTreeMap::new();
        assert_eq!(
            resource_name_annotation(&annotations, LB_FORWARDING_RULE_ANNOTATION_KEY).unwrap(),
            None
        );

        annotations.insert(
            LB_FORWARDING_RULE_ANNOTATION_KEY.to_string(),
            "forwarding-rule-default-web-1234".to_string(),
        );
        assert_eq!(
            resource_name_annotation(&annotations, LB_FORWARDING_RULE_ANNOTATION_KEY)
                .unwrap()
                .map(String::as_str),
            Some("forwarding-rule-default-web-1234")
        );

        annotations.insert(LB_FORWARDING_RULE_ANNOTATION_KEY.to_string(), String::new());
        let empty_err = resource_name_annotation(&annotations, LB_FORWARDING_RULE_ANNOTATION_KEY)
            .unwrap_err()
            .to_string();
        assert!(empty_err.contains(LB_FORWARDING_RULE_ANNOTATION_KEY));

        annotations.insert(
            LB_FORWARDING_RULE_ANNOTATION_KEY.to_string(),
            "x/../../../../global/addresses/victim-ip".to_string(),
        );
        let malicious_err =
            resource_name_annotation(&annotations, LB_FORWARDING_RULE_ANNOTATION_KEY)
                .unwrap_err()
                .to_string();
        assert!(malicious_err.contains(LB_FORWARDING_RULE_ANNOTATION_KEY));
    }

    #[test]
    fn display_untrusted_escapes_control_chars_and_truncates() {
        let escaped = display_untrusted("bad\nvalue\t\x00");
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\t'));
        assert!(!escaped.contains('\0'));
        assert!(escaped.contains("\\n"));
        assert!(escaped.contains("\\t"));

        let long_input = "x".repeat(MAX_LOGGED_VALUE_LEN * 3);
        let truncated = display_untrusted(&long_input);
        assert!(truncated.chars().count() <= MAX_LOGGED_VALUE_LEN);
        assert!(truncated.ends_with("...\""));

        let long_controls = "\n".repeat(MAX_LOGGED_VALUE_LEN);
        let truncated_controls = display_untrusted(&long_controls);
        assert!(truncated_controls.chars().count() <= MAX_LOGGED_VALUE_LEN);
        assert!(!truncated_controls.contains('\n'));
    }
}
