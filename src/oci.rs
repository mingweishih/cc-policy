// Copyright (c) Cc-Policy Authors.
// Licensed under the Apache 2.0 license.

use anyhow::{Context, Result};
use oci_spec::runtime::{Process, Spec};

pub fn empty_process() -> Result<Process> {
    let process: Process = serde_json::from_str(
        r#"{
        "user": {
            "uid": 0,
            "gid": 0   
        },
        "cwd": ""
    }"#,
    )
    .context(loc!())?;

    Ok(process)
}

pub fn empty_spec() -> Result<Spec> {
    let spec: Spec = serde_json::from_str(
        r#"{
                "ociVersion": ""
            }"#,
    )
    .context(loc!())?;

    Ok(spec)
}
