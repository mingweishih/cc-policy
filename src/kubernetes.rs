// Copyright (c) Cc-Policy Authors.
// Licensed under the Apache 2.0 license.

use anyhow::Result;
use oci_spec::runtime::{Process, Spec};

// The default image version of the pause container is based
// on https://github.com/kubernetes/kubernetes/blob/release-1.23/cmd/kubeadm/app/constants/constants.go#L415
// The Kubernetes version (currently 1.23) is based on
// https://github.com/kata-containers/kata-containers/blob/CCv0/versions.yaml#L243
pub const KUBERNETES_PAUSE_VERSION: &str = "3.6";
pub const KUBERNETES_PAUSE_NAME: &str = "pause";
pub const KUBERNETES_REGISTRY: &str = "registry.k8s.io";

fn get_container_rules() -> Result<Spec> {
    let mut spec: Spec = serde_json::from_str("{}")?;

    // Initialize with necessary fields
    let mut process: Process = serde_json::from_str(
        r#"{
        "user": {
            "uid": 0,
            "gid": 0   
        },
        "cwd": ""
    }"#,
    )?;

    // Add environment variables that allow the container to find services
    // Reference: https://github.com/kubernetes/kubernetes/blob/release-1.26/pkg/kubelet/envvars/envvars.go#L32
    let env = [
        "^[A-Z0-9_]+_SERVICE_HOST=^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d).?\\b){4}$",
        "^[A-Z0-9_]+_SERVICE_PORT=[0-9]+",
        "^[A-Z0-9_]+_SERVICE_PORT_[A-Z]+=[0-9]+",
        "^[A-Z0-9_]+_PORT=[a-z]+://^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d).?\\b){4}:[0-9]+",
        "^[A-Z0-9_]+_PORT_[0-9]+_[A-Z]+=[a-z]+://^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d).?\\b){4}:[0-9]+",
        "^[A-Z0-9_]+_PORT_[0-9]+_[A-Z]+_PROTO=[a-z]+",
        "^[A-Z0-9_]+_PORT_[0-9]+_[A-Z]+_PORT=[0-9]+",
        "^[A-Z0-9_]+_PORT_[0-9]+_[A-Z]+_ADDR=^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d).?\\b){4}$" 
    ].map(String::from).to_vec();

    process.set_env(Some(env));

    spec.set_process(Some(process));

    // TODO: Add reference
    let mounts = serde_json::from_str(
        r#"
    [
        {
            "destination": "/dev/termination-log",
            "source": "^/run/kata-containers/shared/containers/[a-z0-9]+-[a-z0-9]+-termination-log$",
            "type": "bind",
            "options": [
                "rbind",
                "rprivate",
                "rw"
            ]
        },
        {
            "destination": "/var/run/secrets/kubernetes.io/serviceaccount",
            "source": "^/run/kata-containers/shared/containers/[a-z0-9]+-[a-z0-9]+-serviceaccount$",
            "type": "bind",
            "options": [
                "rbind",
                "rprivate",
                "ro"
            ]
        }
    ]
    "#,
    )?;

    spec.set_mounts(Some(mounts));

    Ok(spec)
}

// TODO: Check if there is any sandbox-specific insertions
fn get_sandbox_rules() -> Result<Spec> {
    let spec = serde_json::from_str("{}")?;

    Ok(spec)
}

pub fn get_rules(is_sandbox: bool) -> Result<Spec> {
    if !is_sandbox {
        get_container_rules()
    } else {
        get_sandbox_rules()
    }
}

pub fn get_pause_image_ref() -> String {
    [
        KUBERNETES_REGISTRY,
        "/",
        KUBERNETES_PAUSE_NAME,
        ":",
        KUBERNETES_PAUSE_VERSION,
    ]
    .concat()
}
